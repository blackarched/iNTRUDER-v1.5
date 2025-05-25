# server.py
"""
Main server entrypoint for iNTRUDER v1.5 with integrated plugins:
- Rogue AP
- MITM proxy
- WPS attack
- Deauth attack
- Handshake capture
- Wi-Fi cracking
Provides RESTful API endpoints and WebSocket events for dashboard control.
"""
import os
import signal
import logging
import subprocess
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from backend.plugins.rogue_ap import RogueAP
from backend.plugins.mitm import MitmProxy
from backend.plugins.wps_attack import WPSAttack
from backend.deauth_attack import DeauthAttack
from backend.handshake import HandshakeCapture
from backend.wifi_cracker import WifiCracker

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("server")

# Flask + SocketIO setup
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global process/state holders
_services = {}

# Graceful shutdown
def shutdown_handler(signum, frame):
    logger.info("Shutting down iNTRUDER server and all services...")
    for name, svc in _services.items():
        try:
            svc.shutdown() if hasattr(svc, 'shutdown') else svc.cleanup()
            logger.info(f"Stopped {name}")
        except Exception:
            logger.exception(f"Error stopping {name}")
    os._exit(0)

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

# Endpoint: Start Rogue AP
@app.route('/api/rogue_ap/start', methods=['POST'])
def api_start_rogue_ap():
    data = request.json
    iface = data.get('iface')
    ssid = data.get('ssid')
    channel = data.get('channel', 6)

    ap = RogueAP(iface=iface, ssid=ssid, channel=channel)
    procs = ap.start_services()
    _services['rogue_ap'] = ap
    return jsonify({'status': 'running', 'procs': list(procs.keys())}), 200

# Endpoint: Stop Rogue AP
@app.route('/api/rogue_ap/stop', methods=['POST'])
def api_stop_rogue_ap():
    ap = _services.pop('rogue_ap', None)
    if not ap:
        return jsonify({'error': 'Rogue AP not running'}), 400
    ap.cleanup()
    return jsonify({'status': 'stopped'}), 200

# Endpoint: Start MITM Proxy
@app.route('/api/mitm/start', methods=['POST'])
def api_start_mitm():
    data = request.json
    port = data.get('port', 8081)
    mode = data.get('mode', 'transparent')

    mitm = MitmProxy(listen_port=port, mode=mode)
    mitm.start()
    _services['mitm'] = mitm
    return jsonify({'status': 'running', 'port': port}), 200

# Endpoint: Stop MITM Proxy
@app.route('/api/mitm/stop', methods=['POST'])
def api_stop_mitm():
    mitm = _services.pop('mitm', None)
    if not mitm:
        return jsonify({'error': 'MITM not running'}), 400
    mitm.shutdown()
    return jsonify({'status': 'stopped'}), 200

# Endpoint: Start WPS Attack
@app.route('/api/wps/start', methods=['POST'])
def api_start_wps():
    data = request.json
    iface = data.get('iface')
    bssid = data.get('bssid')
    timeout = data.get('timeout', 3600)
    multi = data.get('multi', False)

    wps = WPSAttack(iface=iface, target_bssid=bssid)
    _services['wps'] = wps
    code = wps.run(timeout=timeout, multi=multi)
    return jsonify({'status': 'completed', 'exit_code': code}), 200

# Endpoint: Deauthentication Attack
@app.route('/api/deauth/start', methods=['POST'])
def api_start_deauth():
    data = request.json
    iface = data.get('interface') # Changed from 'iface'
    ap_bssid = data.get('bssid')    # Changed from 'target'
    client_mac_from_req = data.get('client')
    client_mac = client_mac_from_req if client_mac_from_req else None # Pass None if empty
    
    # Ensure count is an integer, default to 10 if not provided or invalid
    try:
        count = int(data.get('count', 10))
    except (ValueError, TypeError):
        count = 10

    # Ensure ap_bssid is provided
    if not ap_bssid:
        return jsonify({'status': 'error', 'message': 'BSSID (ap_bssid) is required for deauth attack.'}), 400
    if not iface:
        return jsonify({'status': 'error', 'message': 'Interface (iface) is required for deauth attack.'}), 400


    deauth = DeauthAttack(iface=iface, ap_bssid=ap_bssid, count=count, client_mac=client_mac)
    _services['deauth'] = deauth
    # The DeauthAttack class's run() method returns a dictionary.
    # The original code returned result in 'sent': result.
    # The DeauthAttack class already returns a dict with status, message, etc.
    # So we can return that directly or wrap it. Let's return it directly for more info.
    result_dict = deauth.run() 
    
    # Determine HTTP status code based on attack result status
    response_status_code = 200
    if result_dict.get('status') == 'error' or result_dict.get('status') == 'exception':
        response_status_code = 500 # Internal Server Error for attack failures
    elif result_dict.get('status') == 'pending_parse' : # Example if it could be pending
        response_status_code = 202 # Accepted

    return jsonify(result_dict), response_status_code

# Endpoint: Capture Handshake (now /api/scan-handshake)
@app.route('/api/scan-handshake', methods=['POST']) # Renamed route
def api_scan_handshake(): # Renamed function for clarity, though not strictly necessary
    data = request.json
    iface = data.get('iface')
    ssid = data.get('ssid') # SSID is optional for HandshakeCapture

    if not iface:
        return jsonify({'status': 'error', 'message': 'Interface (iface) is required for handshake capture.'}), 400

    try:
        hs = HandshakeCapture(iface=iface, ssid=ssid if ssid else None)
        _services['handshake'] = hs # Storing the instance
        
        # The HandshakeCapture class's capture() method is expected to return a path to the .cap file
        # or raise an exception/return an error structure.
        # Assuming it returns a path on success and we handle its errors if it raises them or returns None/error dict
        
        capture_result = hs.capture() # This might be a dict or a path string

        # Based on existing pattern, assuming capture() returns a path string on success
        # and we might need to adapt if HandshakeCapture.capture() has its own error dict.
        # For now, sticking to the old success structure if path is returned.
        # If HandshakeCapture.capture() itself returns a dict like other new classes, this part would change.
        # Given the subtask focuses on server.py args and HandshakeCapture class is refactored later,
        # we'll assume it returns a path string for now.
        
        if isinstance(capture_result, str) and capture_result.endswith(".cap"): # Simple check for path
            return jsonify({'status': 'captured', 'file': capture_result}), 200
        elif isinstance(capture_result, dict) and 'status' in capture_result: # If HandshakeCapture.capture returns a dict
            return jsonify(capture_result), 500 if capture_result['status'] == 'error' else 200
        else: # Fallback or if capture_result indicates an error in a non-dict way
            logger.error(f"Handshake capture failed or returned unexpected result: {capture_result}")
            return jsonify({'status': 'error', 'message': 'Handshake capture failed.', 'details': str(capture_result)}), 500

    except Exception as e:
        logger.error(f"Error during handshake capture: {str(e)}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred during handshake capture.', 'details': str(e)}), 500

# Endpoint: Wi-Fi Cracking
@app.route('/api/crack/start', methods=['POST'])
def api_start_crack():
    data = request.json
    handshake_file = data.get('handshake') # Changed key from 'handshake_file'
    wordlist = data.get('wordlist')

    if not handshake_file:
        return jsonify({'status': 'error', 'message': 'Handshake file path (handshake) is required.'}), 400
    if not wordlist:
        return jsonify({'status': 'error', 'message': 'Wordlist file path (wordlist) is required.'}), 400

    try:
        cracker = WifiCracker(handshake_file=handshake_file, wordlist=wordlist)
        _services['cracker'] = cracker
        result_dict = cracker.run() # WifiCracker.run() now returns a dictionary

        response_status_code = 200
        if result_dict.get('status') == 'error' or result_dict.get('status') == 'exception':
            response_status_code = 500
        # 'success' (password found) or 'failure' (password not found) are both 200 OK from API perspective
        
        return jsonify(result_dict), response_status_code

    except Exception as e:
        logger.error(f"Error during Wi-Fi cracking: {str(e)}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred during Wi-Fi cracking.', 'details': str(e)}), 500

# Endpoint: Start Monitor Mode
@app.route('/api/start-monitor', methods=['POST'])
def api_start_monitor():
    try:
        # Path to the script - assuming it's in the root directory and executable
        script_path = './start-mon.sh'
        
        process_result = subprocess.run(
            [script_path],
            capture_output=True,
            text=True,
            check=False # Do not raise exception on non-zero exit
        )
        
        if process_result.returncode == 0:
            return jsonify({
                'status': 'success',
                'message': 'Monitor mode script executed successfully. Interface wlan0mon should be up.',
                'stdout': process_result.stdout.strip(),
                'stderr': process_result.stderr.strip()
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to execute monitor mode script.',
                'stdout': process_result.stdout.strip(),
                'stderr': process_result.stderr.strip(),
                'returncode': process_result.returncode
            }), 500

    except FileNotFoundError:
        return jsonify({
            'status': 'error',
            'message': f'Error: {script_path} not found. Ensure it exists and path is correct.',
            'details': f'{script_path} not found'
        }), 404
    except Exception as e:
        logger.error(f"Error in /api/start-monitor: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred.',
            'details': str(e)
        }), 500

@app.route('/api/scan-networks', methods=['POST']) # Or GET, but POST is used by frontend for others
def api_scan_networks():
    # Interface should ideally be a parameter, but airodump-ng in scan.sh uses wlan0mon
    # For now, let's assume wlan0mon is the interface to use.
    # This command will be run with a timeout.
    # airodump-ng will write CSV files (e.g., scan_results-01.csv) in the root directory.
    # We also need to handle cleanup of these files.
    
    interface_to_scan = "wlan0mon" # Hardcoded for now, similar to scan.sh
    output_prefix = "scan_results_api" # Use a unique prefix for files from API
    scan_duration = 15  # seconds for airodump-ng to run
    
    # Command to run airodump-ng
    # --write-interval 5: save file every 5s. With a 15s scan, it might write 2-3 times.
    # --background 1: tells airodump-ng to run in background and self-terminate after some time (requires specific version)
    # The --background option is not standard for all versions.
    # A more reliable way is to use subprocess timeout.
    cmd = [
        "sudo", "airodump-ng", interface_to_scan,
        "--write", output_prefix,
        "--output-format", "csv",
        "--write-interval", "5" # Write more frequently
    ]
    
    try:
        # Start airodump-ng and let it run for scan_duration seconds
        logger.info(f"Starting network scan with command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        stdout = ""
        stderr = ""
        returncode = -1 # Default to indicate timeout or other issue before communicate finishes

        try:
            # Wait for the process to complete or timeout
            stdout, stderr = process.communicate(timeout=scan_duration)
            returncode = process.returncode # Will be non-zero if killed by timeout typically
            logger.info(f"Scan stdout: {stdout}")
            logger.info(f"Scan stderr: {stderr}")

        except subprocess.TimeoutExpired:
            logger.info("Scan process timed out, terminating.")
            process.terminate() # Terminate the process
            try:
                # Wait a bit for termination then kill if necessary
                process.wait(timeout=5) 
            except subprocess.TimeoutExpired:
                process.kill() # Force kill
            
            # Try to get any remaining output after terminate/kill
            try:
                stdout_after_timeout, stderr_after_timeout = process.communicate(timeout=1)
                stdout += stdout_after_timeout
                stderr += stderr_after_timeout
            except Exception as e_comm: # Catch errors from communicate if process already dead
                 logger.info(f"Error getting output after timeout: {str(e_comm)}")

            logger.info(f"Scan stdout after timeout: {stdout}")
            logger.info(f"Scan stderr after timeout: {stderr}")
            returncode = -9 # Indicate timeout explicitly (SIGKILL is often -9)
            # Even on timeout, a CSV might have been written.

        # At this point, airodump-ng has run for some time.
        # We need to find the CSV file it created.
        # The filename will be like 'scan_results_api-01.csv'.
        # We'll look for the latest one.
        
        # Basic: For now, just return the fact that scan was run.
        # Parsing the CSV and returning structured data will be a follow-up.
        # Also, cleanup of scan_results_api-* files is needed.
        
        # For now, a simple response:
        return jsonify({
            'status': 'pending_parse', # Indicates scan run, but parsing not yet implemented here
            'message': f'Network scan initiated for {scan_duration}s. Output files prefix: {output_prefix}. Parsing of results is the next step.',
            'stdout': stdout,
            'stderr': stderr,
            'returncode': returncode
        }), 200

    except FileNotFoundError:
        return jsonify({
            'status': 'error',
            'message': 'Error: airodump-ng command not found. Is aircrack-ng suite installed and in PATH?',
        }), 404
    except Exception as e:
        logger.error(f"Error in /api/scan-networks: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred during network scan.',
            'details': str(e)
        }), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200

# SocketIO example: real-time logs
@socketio.on('connect')
def on_connect():
    logger.info('Dashboard client connected')
    socketio.emit('status', {'services': list(_services.keys())})

if __name__ == '__main__':
    port = int(os.environ.get('INTRUDER_PORT', 5000))
    debug = os.environ.get('INTRUDER_DEBUG', 'False') == 'True'
    logger.info(f"Starting iNTRUDER server on port {port}, debug={debug}")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)
