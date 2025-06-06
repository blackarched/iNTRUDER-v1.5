#!/usr/bin/env python3
# server.py
"""
Main server entrypoint for iNTRUDER v1.5.

Provides RESTful API endpoints and WebSocket events for dashboard control
of integrated plugins.

Required Dependencies:
- Flask
- Flask-CORS
- Flask-SocketIO
- backend.rogue_ap
- backend.mitm
- backend.wps_attack
- backend.deauth_attack
- backend.handshake
- backend.wifi_cracker

Expected Environment Variables:
- INTRUDER_PORT: Port for the Flask server (default: 5000).
- INTRUDER_DEBUG: Set to 'True' to enable Flask debug mode (default: 'False').
"""
import os
import signal
import logging
from types import FrameType
from typing import Dict, Any, Optional, Tuple

from flask import Flask, jsonify, request, send_from_directory, Response as FlaskResponse
from flask_cors import CORS
from flask_socketio import SocketIO

# Assuming backend modules are corrected to be directly under backend/
from backend.rogue_ap import RogueAP
from backend.mitm import MitmProxy # Corrected import
from backend.wps_attack import WPSAttack # Corrected import
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
# Serve static files from 'dashboard' and templates from 'dashboard'
app = Flask(__name__, template_folder='dashboard', static_folder='dashboard')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global process/state holders
_services: Dict[str, Any] = {}

def shutdown_handler(signum: int, frame: Optional[FrameType]) -> None:
    """
    Handles SIGINT and SIGTERM signals for graceful shutdown of the server
    and all running services.
    """
    logger.info("Shutting down iNTRUDER server and all services...")
    for name, svc in list(_services.items()): # Iterate over a copy
        try:
            if hasattr(svc, 'shutdown'):
                svc.shutdown()
            elif hasattr(svc, 'cleanup'):
                svc.cleanup()
            else:
                logger.warning(f"Service {name} has no shutdown or cleanup method.")
            logger.info(f"Stopped {name}")
        except Exception: # pylint: disable=broad-except
            logger.exception(f"Error stopping {name}")
        if name in _services: # remove if stop was successful
            _services.pop(name, None)
    logger.info("All services attempted to stop. Exiting.")
    os._exit(0) # Force exit if threads are stuck

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

# Serve main dashboard page
@app.route('/', methods=['GET'])
def index() -> FlaskResponse:
    """Serves the main dashboard HTML page."""
    # Ensure app.template_folder is an absolute path or correctly relative
    # Flask's send_from_directory expects directory as first arg.
    # template_folder is usually relative to app root.
    return send_from_directory(app.template_folder, 'index.html')

# Endpoint: Start Rogue AP
@app.route('/api/rogue_ap/start', methods=['POST'])
def api_start_rogue_ap() -> Tuple[FlaskResponse, int]:
    """
    Starts the Rogue AP service.
    Expects JSON: {'iface': str, 'ssid': str, 'channel': Optional[int]}
    """
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400

    iface = data.get('iface')
    ssid = data.get('ssid')
    channel = data.get('channel', 6) # Default channel 6

    if not iface:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: iface'}), 400
    if not ssid:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: ssid'}), 400

    try:
        ap = RogueAP(iface=iface, ssid=ssid, channel=channel)
        procs = ap.start_services() # Assuming this returns relevant info
        _services['rogue_ap'] = ap
        logger.info(f"Rogue AP started on {iface} with SSID {ssid}")
        return jsonify({'status': 'success', 'message': 'Rogue AP starting', 'details': {'procs': list(procs.keys())}}), 200
    except Exception as e: # pylint: disable=broad-except
        logger.exception("Failed to start Rogue AP")
        return jsonify({'status': 'error', 'message': f'Failed to start Rogue AP: {str(e)}'}), 500

# Endpoint: Stop Rogue AP
@app.route('/api/rogue_ap/stop', methods=['POST'])
def api_stop_rogue_ap() -> Tuple[FlaskResponse, int]:
    """Stops the Rogue AP service."""
    ap = _services.pop('rogue_ap', None)
    if not ap:
        return jsonify({'status': 'error', 'message': 'Rogue AP not running or already stopped'}), 400
    try:
        ap.cleanup()
        logger.info("Rogue AP stopped successfully.")
        return jsonify({'status': 'success', 'message': 'Rogue AP stopped'}), 200
    except Exception as e: # pylint: disable=broad-except
        logger.exception("Failed to stop Rogue AP")
        # Add service back if cleanup failed, to allow another try or manual check
        _services['rogue_ap'] = ap
        return jsonify({'status': 'error', 'message': f'Failed to stop Rogue AP: {str(e)}'}), 500

# Endpoint: Start MITM Proxy
@app.route('/api/mitm/start', methods=['POST'])
def api_start_mitm() -> Tuple[FlaskResponse, int]:
    """
    Starts the MITM Proxy service.
    Expects JSON: {'port': Optional[int], 'mode': Optional[str]}
    """
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400

    port = data.get('port', 8081) # Default port for MITM
    mode = data.get('mode', 'transparent')

    try:
        mitm = MitmProxy(listen_port=port, mode=mode)
        mitm.start() # Assuming this is a non-blocking start or handled internally
        _services['mitm'] = mitm
        logger.info(f"MITM proxy started on port {port} in {mode} mode.")
        return jsonify({'status': 'success', 'message': 'MITM proxy starting', 'details': {'port': port, 'mode': mode}}), 200
    except Exception as e: # pylint: disable=broad-except
        logger.exception("Failed to start MITM proxy")
        return jsonify({'status': 'error', 'message': f'Failed to start MITM proxy: {str(e)}'}), 500

# Endpoint: Stop MITM Proxy
@app.route('/api/mitm/stop', methods=['POST'])
def api_stop_mitm() -> Tuple[FlaskResponse, int]:
    """Stops the MITM Proxy service."""
    mitm = _services.pop('mitm', None)
    if not mitm:
        return jsonify({'status': 'error', 'message': 'MITM proxy not running or already stopped'}), 400
    try:
        mitm.shutdown()
        logger.info("MITM proxy stopped successfully.")
        return jsonify({'status': 'success', 'message': 'MITM proxy stopped'}), 200
    except Exception as e: # pylint: disable=broad-except
        logger.exception("Failed to stop MITM proxy")
        _services['mitm'] = mitm # Add back if failed
        return jsonify({'status': 'error', 'message': f'Failed to stop MITM proxy: {str(e)}'}), 500

# Endpoint: Start WPS Attack
@app.route('/api/wps/start', methods=['POST'])
def api_start_wps() -> Tuple[FlaskResponse, int]:
    """
    Starts the WPS PIN attack.
    Expects JSON: {'iface': str, 'bssid': str, 'timeout': Optional[int], 'multi': Optional[bool]}
    Note: This is likely a blocking operation. Consider async task.
    """
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400

    iface = data.get('iface')
    bssid = data.get('bssid')
    timeout = data.get('timeout', 3600) # Default 1 hour
    multi = data.get('multi', False)

    if not iface:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: iface'}), 400
    if not bssid:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: bssid'}), 400

    # This is a blocking call, client will wait. Consider Celery/RQ for async.
    try:
        wps = WPSAttack(iface=iface, target_bssid=bssid)
        _services['wps_instance'] = wps # Store instance if needed, though it's blocking
        logger.info(f"Starting WPS attack on {bssid} via {iface}.")
        # result = wps.run(timeout=timeout, multi=multi) # Assuming run is blocking and returns result
        # For now, let's assume wps.run() is called by the module's own CLI or needs a wrapper for subprocess.
        # The current server.py calls it directly, which will block the server worker.
        # This should ideally be handled by the WPSAttack module to run Reaver and manage output.
        # For the purpose of this audit, we'll assume the WPSAttack class handles its subprocess calls correctly.
        # The server's role is to invoke it. If WPSAttack.run() is not robust, it will be fixed in that module's audit.
        # For now, let's simulate what was there:
        result_code = wps.run(timeout=timeout, multi=multi) # Placeholder for actual result structure
        logger.info(f"WPS attack completed for {bssid}. Result code: {result_code}")
        _services.pop('wps_instance', None) # Clean up
        return jsonify({'status': 'success', 'message': 'WPS attack completed', 'details': {'exit_code': result_code}}), 200
    except Exception as e: # pylint: disable=broad-except
        logger.exception("WPS attack failed")
        _services.pop('wps_instance', None) # Clean up
        return jsonify({'status': 'error', 'message': f'WPS attack failed: {str(e)}'}), 500


# Endpoint: Deauthentication Attack
@app.route('/api/deauth/start', methods=['POST'])
def api_start_deauth() -> Tuple[FlaskResponse, int]:
    """
    Starts a deauthentication attack.
    Expects JSON: {'iface': str, 'target': str, 'count': Optional[int]}
    Note: This is likely a blocking operation.
    """
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400

    iface = data.get('iface')
    target_mac = data.get('target')  # MAC to deauth
    count = data.get('count', 10) # Default 10 packets

    if not iface:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: iface'}), 400
    if not target_mac:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: target (target MAC)'}), 400

    try:
        deauth = DeauthAttack(iface=iface, target_mac=target_mac, count=count)
        _services['deauth_instance'] = deauth # Store instance
        logger.info(f"Starting deauth attack on {target_mac} via {iface}.")
        # result = deauth.run() # Assuming run is blocking and returns result
        # Similar to WPS, DeauthAttack.run() will be audited later.
        sent_packets = deauth.run() # Placeholder
        logger.info(f"Deauth attack completed against {target_mac}. Sent: {sent_packets}")
        _services.pop('deauth_instance', None)
        return jsonify({'status': 'success', 'message': 'Deauth attack completed', 'details': {'sent_packets': sent_packets}}), 200
    except Exception as e: # pylint: disable=broad-except
        logger.exception("Deauth attack failed")
        _services.pop('deauth_instance', None)
        return jsonify({'status': 'error', 'message': f'Deauth attack failed: {str(e)}'}), 500

# Endpoint: Capture Handshake
@app.route('/api/handshake/start', methods=['POST'])
def api_start_handshake() -> Tuple[FlaskResponse, int]:
    """
    Starts handshake capture.
    Expects JSON: {'iface': str, 'ssid': str}
    Note: This is likely a blocking operation.
    """
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400

    iface = data.get('iface')
    ssid = data.get('ssid') # Target SSID for capture

    if not iface:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: iface'}), 400
    if not ssid:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: ssid'}), 400

    try:
        hs = HandshakeCapture(iface=iface, ssid=ssid)
        _services['handshake_instance'] = hs
        logger.info(f"Starting handshake capture for SSID {ssid} on {iface}.")
        # file_path = hs.capture() # Assuming run is blocking and returns result
        # HandshakeCapture.capture() will be audited later.
        file_path = hs.capture() # Placeholder
        logger.info(f"Handshake captured for {ssid}. File: {file_path}")
        _services.pop('handshake_instance', None)
        return jsonify({'status': 'success', 'message': 'Handshake capture completed', 'details': {'file_path': file_path}}), 200
    except Exception as e: # pylint: disable=broad-except
        logger.exception("Handshake capture failed")
        _services.pop('handshake_instance', None)
        return jsonify({'status': 'error', 'message': f'Handshake capture failed: {str(e)}'}), 500

# Endpoint: Wi-Fi Cracking
@app.route('/api/crack/start', methods=['POST'])
def api_start_crack() -> Tuple[FlaskResponse, int]:
    """
    Starts Wi-Fi password cracking.
    Expects JSON: {'handshake_file': str, 'wordlist': str}
    Note: This is likely a blocking operation.
    """
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'Request must be JSON'}), 400

    handshake_file = data.get('handshake_file')
    wordlist = data.get('wordlist')

    if not handshake_file:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: handshake_file'}), 400
    if not wordlist:
        return jsonify({'status': 'error', 'message': 'Missing required parameter: wordlist'}), 400

    # Basic validation for file existence could be added here if paths are server-local
    # However, paths might be relative to a volume or user-provided context.
    # The backend module should handle path validation robustly.

    try:
        cracker = WifiCracker(handshake_file=handshake_file, wordlist=wordlist)
        _services['cracker_instance'] = cracker
        logger.info(f"Starting Wi-Fi cracking for {handshake_file} using {wordlist}.")
        # password = cracker.run() # Assuming run is blocking and returns result
        # WifiCracker.run() will be audited later.
        password_found = cracker.run() # Placeholder
        logger.info(f"Wi-Fi cracking completed for {handshake_file}. Password: {'Found' if password_found else 'Not Found'}")
        _services.pop('cracker_instance', None)
        return jsonify({'status': 'success', 'message': 'Wi-Fi cracking process completed.', 'details': {'password': password_found}}), 200
    except Exception as e: # pylint: disable=broad-except
        logger.exception("Wi-Fi cracking failed")
        _services.pop('cracker_instance', None)
        return jsonify({'status': 'error', 'message': f'Wi-Fi cracking failed: {str(e)}'}), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health() -> Tuple[FlaskResponse, int]:
    """Provides a simple health check endpoint."""
    logger.debug("Health check requested.")
    return jsonify({'status': 'success', 'message': 'Server is healthy'}), 200

# SocketIO example: real-time status/logs
@socketio.on('connect')
def on_connect() -> None:
    """Handles new client WebSocket connections."""
    logger.info('Dashboard client connected via WebSocket.')
    # Emit current status, e.g., list of active services
    active_services = {name: True for name in _services} # Basic status
    socketio.emit('status_update', {'services': active_services})

@socketio.on('disconnect')
def on_disconnect() -> None:
    """Handles client WebSocket disconnections."""
    logger.info('Dashboard client disconnected from WebSocket.')

if __name__ == '__main__':
    try:
        port = int(os.environ.get('INTRUDER_PORT', "5000")) # Default to string for get
        debug_str = os.environ.get('INTRUDER_DEBUG', 'False')
        debug = debug_str.lower() in ('true', '1', 't')
    except ValueError:
        logger.warning("INTRUDER_PORT environment variable is not a valid integer. Using default 5000.")
        port = 5000
        debug = False # Default debug to False on port parse error

    logger.info(f"Starting iNTRUDER server on host 0.0.0.0 port {port}, debug={debug}")
    # Use a production-ready WSGI server like gunicorn or uwsgi for real deployment
    # For development, socketio.run(app) is fine.
    # Consider adding use_reloader=debug to socketio.run if appropriate for dev
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, use_reloader=False)
