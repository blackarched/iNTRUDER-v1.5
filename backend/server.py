#!/usr/bin/env python3
# server.py
"""
Main server entrypoint for iNTRUDER v1.5 with integrated plugins:
- Rogue AP

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

from . import config # Import the configuration
import sys # For StreamHandler output to stdout

# --- Root Logger Configuration ---
# Determine numeric log level
numeric_level = getattr(logging, config.LOG_LEVEL.upper(), None)
if not isinstance(numeric_level, int):
    numeric_level = logging.INFO # Default to INFO if level is invalid

log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# Get the root logger
root_logger = logging.getLogger()
root_logger.setLevel(numeric_level)
# Clear any existing handlers to avoid duplicate logs if this script is re-run in some environments
if root_logger.hasHandlers():
    root_logger.handlers.clear()

# Console Handler
console_handler = logging.StreamHandler(sys.stdout) # Log to stdout
console_handler.setFormatter(log_formatter)
root_logger.addHandler(console_handler)

# File Handler
# Ensures log file path is relative to where the server is run (expected to be project root)
try:
    file_handler = logging.FileHandler(config.LOG_FILE, mode='a') # Append mode
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)
except Exception as e:
    # If file handler fails (e.g. permissions), log to console about it
    root_logger.error(f"Failed to configure file logger at {config.LOG_FILE}: {e}", exc_info=True)

# Get a logger for this specific module (server.py) after root configuration
logger = logging.getLogger(__name__)
# --- End Root Logger Configuration ---

from .plugins.rogue_ap import RogueAP

from .plugins.wps_attack import WPSAttack
from .plugins.opsec_utils import MACChanger
from .plugins.scanner import AdaptiveScanner # Import AdaptiveScanner
from .deauth_attack import DeauthAttack
from .handshake_capture_module import HandshakeCapture
from .wifi_cracker_module import WifiCracker
from .core.event_logger import log_event
from .core.network_utils import interface_exists, is_monitor_mode # Import for interface checks
from .reporting import ReportGenerator # Import for reporting

# Flask + SocketIO setup
app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global process/state holders
_services = {}

# Graceful shutdown
def shutdown_handler(signum, frame):
    logger.info("Received signal %s. Shutting down iNTRUDER server and all services...", signal.Signals(signum).name)
    for name, svc in list(_services.items()): # Iterate over a copy
        logger.info(f"Attempting to stop service: {name}...")
        try:
            if hasattr(svc, 'shutdown'):
                svc.shutdown()
            elif hasattr(svc, 'cleanup'): # Fallback for plugins that use 'cleanup'
                svc.cleanup()
            logger.info(f"Successfully stopped {name}")
        except Exception:
            logger.exception(f"Error stopping {name}")
        finally:
            _services.pop(name, None) # Remove from active services

    logger.info("All services processed. Exiting.")
    sys.exit(0) # Forcing exit, as some subprocesses or threads might hang

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

@app.route('/')
def serve_index():
    # app.static_folder is already set to '../frontend'
    return app.send_static_file('index.html')



@app.errorhandler(400)
def bad_request_error(error):
    response = jsonify(message=error.description or "Bad Request")
    response.status_code = 400
    return response

@app.errorhandler(404)
def not_found_error(error):
    response = jsonify(message=error.description or "Resource not found")
    response.status_code = 404
    return response

@app.errorhandler(405)
def method_not_allowed_error(error):
    response = jsonify(message=error.description or "Method Not Allowed")
    response.status_code = 405
    return response

@app.errorhandler(500)
def internal_error(error):
    # Log the exception error.original_exception if available
    logger.error(f"Server Error: {error}", exc_info=True)
    response = jsonify(message="Internal server error")
    response.status_code = 500
    return response


# Endpoint: Start Rogue AP
@app.route('/api/rogue_ap/start', methods=['POST'])
def api_start_rogue_ap():
    data = request.json
    iface = data.get('iface')
    ssid = data.get('ssid')
    channel = data.get('channel', 6)

    ap = RogueAP(iface=iface, ssid=ssid, channel=channel)
    # RogueAP.start_services() itself logs "rogue_ap_started"
    # We can log the API call initiation here if needed, but internal log might be enough.
    # For consistency, let's add an API-level event.
    log_event("rogue_ap_start_requested", {"interface": iface, "ssid": ssid, "channel": channel})
    procs = ap.start_services() # This logs "rogue_ap_started"
    _services['rogue_ap'] = ap
    return jsonify({'status': 'running', 'procs': list(procs.keys())}), 200

# Endpoint: Stop Rogue AP
@app.route('/api/rogue_ap/stop', methods=['POST'])
def api_stop_rogue_ap():
    ap = _services.pop('rogue_ap', None)
    if not ap:
        return jsonify({"status": "error", 'message': 'Rogue AP not running'}), 400 # Consistent error

    # RogueAP.cleanup() logs "rogue_ap_stopping" and "rogue_ap_stopped"
    log_event("rogue_ap_stop_requested", {"interface": getattr(ap, 'iface', 'unknown'), "ssid": getattr(ap, 'ssid', 'unknown')})
    ap.cleanup() # This logs "rogue_ap_stopped"
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
    # WPSAttack.run now returns a dictionary like:
    # {"status": "completed/error", "return_code": ..., "log_file": ..., "command": ..., "message": ...}
    wps_result = wps.run(timeout=timeout, multi=multi)

    success = wps_result.get('status') == 'completed' # Assuming 'completed' means Reaver ran, actual attack success is in logs/return_code
    # Event logging for WPS attack is handled within WPSAttack class itself.

    # Propagate a 500 if the status indicates an error running the tool itself (e.g. not found, immediate crash)
    # If 'completed', it means Reaver ran; its specific outcome (PIN found/not found) is in its logs & return_code.
    http_status_code = 200 if wps_result.get('status') in ['completed', 'error_user_input_related'] else 500 # Be more specific if WPSAttack can return different error types

    return jsonify(wps_result), http_status_code

# Endpoint: Deauthentication Attack
@app.route('/api/deauth/start', methods=['POST'])
def api_start_deauth():
    data = request.json
    iface = data.get('iface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    # target = data.get('target')  # MAC to deauth # Old way
    target_bssid = data.get('target_bssid', data.get('target')) # 'target' for backward compat, prefer 'target_bssid'
    client_mac = data.get('client_mac', 'FF:FF:FF:FF:FF:FF') # Default to broadcast if not specified. DeauthAttack class currently doesn't use this for the actual attack command.
    count = data.get('count', 10)

    if not target_bssid: # Ensure target_bssid is provided
        return jsonify({'status': 'error', 'message': 'Target BSSID (target_bssid) not provided'}), 400

    log_event("deauth_attack_started", {
        "interface": iface,
        "target_bssid": target_bssid,
        "client_mac": client_mac,
        "count": count
    })
    deauth = DeauthAttack(iface=iface, target_mac=target_bssid, count=count) # target_mac in DeauthAttack is BSSID
    _services['deauth'] = deauth
    deauth_result = deauth.run() # This now returns a dict

    # deauth_result example: {"status": "success", "output": stdout, "error_output": stderr, "sent": self.count, "command": cmd}
    success = deauth_result.get('status') == 'success' if isinstance(deauth_result, dict) else False
    log_event("deauth_attack_completed", {
        "interface": iface,
        "target_bssid": target_bssid,
        "client_mac": client_mac, # Logged for intent, even if not directly used by aireplay-ng via DeauthAttack class as of now
        "count": count,
        "success": success,
        "details": deauth_result # Contains command, output, errors etc.
    })
    # Original server returned: jsonify({'status': 'completed', 'sent': result})
    # The new deauth_result is richer and should be returned.
    return jsonify(deauth_result), 200 if success else 500

# Endpoint: Capture Handshake
@app.route('/api/handshake/start', methods=['POST'])
def api_start_handshake():
    data = request.json
    iface = data.get('iface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    ssid = data.get('ssid') # SSID is usually required for targeted capture
    bssid = data.get('bssid') # Target BSSID
    channel = data.get('channel') # Optional: channel for faster targeting

    if not ssid and not bssid: # Need at least one to target capture effectively
        return jsonify({'status': 'error', 'message': 'Either SSID (ssid) or Target BSSID (bssid) must be provided for handshake capture'}), 400

    log_event("handshake_capture_started", {"interface": iface, "ssid": ssid, "bssid": bssid, "channel": channel})

    hs_capture_instance = HandshakeCapture(iface=iface, ssid=ssid, bssid=bssid, channel=channel)
    _services['handshake'] = hs_capture_instance # Store the instance for potential shutdown

    capture_details = hs_capture_instance.capture() # capture method returns a dict

    # capture_details example: {"status": "success", "file": self.cap_file_path, "message": "...", "command": cmd}
    is_successful_capture = capture_details.get("status") == "success" or capture_details.get("status") == "success_with_errors"

    log_event("handshake_capture_completed", {
        "interface": iface,
        "ssid": ssid,
        "bssid": bssid,
        "channel": channel, # Log the channel used
        "success": is_successful_capture,
        "file": capture_details.get('file'),
        "details": capture_details # Contains command, messages, etc.
    })

    return jsonify(capture_details), 200 if is_successful_capture else 500

# Endpoint: Wi-Fi Cracking
@app.route('/api/crack/start', methods=['POST'])
def api_start_crack():
    data = request.json
    handshake_file = data.get('handshake_file')
    wordlist_from_request = data.get('wordlist')
    wordlist_to_use = None

    if wordlist_from_request:
        wordlist_to_use = wordlist_from_request
        # Optional: Validate wordlist_from_request here if desired (existence, readability)
        # For now, assume if user provides it, it's their responsibility.
        logger.info(f"Using wordlist from request: {wordlist_to_use}")
    elif getattr(config, 'DEFAULT_WORDLIST', None): # Check if DEFAULT_WORDLIST is set and not None/empty
        wordlist_to_use = config.DEFAULT_WORDLIST
        logger.info(f"Using DEFAULT_WORDLIST from config: {wordlist_to_use}")
        # validate_config would have warned about this path at startup if it's bad.
        # Add an explicit check here before use for robustness:
        if not os.path.exists(wordlist_to_use) or not os.access(wordlist_to_use, os.R_OK):
            msg = f"DEFAULT_WORDLIST '{wordlist_to_use}' is configured but not found or not readable."
            logger.error(msg)
            log_event("crack_attempt_failed", {"handshake_file": handshake_file, "reason": "Default wordlist invalid", "default_wordlist_path": wordlist_to_use})
            return jsonify({"status": "error", "message": msg}), 500 # Server config issue
    else:
        msg = "Wordlist not provided in request and no DEFAULT_WORDLIST is configured."
        logger.warning(msg)
        log_event("crack_attempt_failed", {"handshake_file": handshake_file, "reason": "No wordlist provided or configured"})
        return jsonify({"status": "error", "message": msg}), 400 # Client error: wordlist required

    if not handshake_file: # This check was already here, good.
        return jsonify({'status': 'error', 'message': 'Handshake file (handshake_file) not provided'}), 400

    log_event("crack_attempt_started", {"handshake_file": handshake_file, "wordlist_used": wordlist_to_use})

    cracker = WifiCracker(handshake_file=handshake_file, wordlist=wordlist_to_use)
    _services['cracker'] = cracker

    crack_result = cracker.run() # This now returns a dict

    # crack_result example: {"status": "success", "password": password, "command": cmd, ...}
    password_found = crack_result.get('status') == 'success' and crack_result.get('password') is not None \
                     if isinstance(crack_result, dict) else False

    log_event("crack_attempt_completed", {
        "handshake_file": handshake_file,
        "wordlist_used": wordlist_to_use,
        "success": password_found,
        "password_found": crack_result.get('password') if password_found else None, # Log password only if found and success
        "details": crack_result
    })

    # Return the rich result from cracker.run()
    return jsonify(crack_result), 200 if crack_result.get('status') in ['success', 'failed'] else 500

# Endpoint: Start Monitor Mode
@app.route('/api/monitor/start', methods=['POST'])
def api_start_monitor():
    data = request.json
    # Use default iface from config if not provided. start-mon.sh typically creates a new mon interface.
    iface_to_mon = data.get('iface', config.DEFAULT_IFACE) # This is the base interface, e.g., wlan0

    # Check if base interface exists BEFORE attempting MAC change or monitor mode.
    if not interface_exists(iface_to_mon):
        msg = f"Base interface {iface_to_mon} not found. Cannot start monitor mode."
        logger.error(msg)
        log_event("monitor_mode_failed", {"interface": iface_to_mon, "reason": "Base interface not found"})
        return jsonify({"status": "error", "message": msg}), 400 # 400 for client error (bad interface)

    original_mac_for_revert = None # To store original MAC if we intend to revert later

    if config.MAC_CHANGE_ENABLED:
        logger.info(f"MAC_CHANGE_ENABLED is True. Attempting to change MAC for {iface_to_mon} before starting monitor mode.")
        mac_changer = MACChanger()
        if mac_changer._check_macchanger_installed(): # Check again or rely on constructor's check
            original_mac = mac_changer.get_current_mac(iface_to_mon)
            if original_mac:
                logger.info(f"Original MAC for {iface_to_mon}: {original_mac}")
                # original_mac_for_revert = original_mac # Store if we plan to add a "stop_monitor" that reverts

                new_mac, _ = mac_changer.set_mac_random(iface_to_mon)
                if new_mac:
                    logger.info(f"Set random MAC for {iface_to_mon}: {new_mac}")
                else:
                    logger.warning(f"Failed to set random MAC for {iface_to_mon}. Proceeding with current/original MAC.")
            else:
                logger.warning(f"Could not get original MAC for {iface_to_mon}. Skipping MAC change.")
        else:
            logger.warning("MACChanger utility is not fully operational (macchanger command not found). Skipping MAC change.")
    else:
        logger.info("MAC_CHANGE_ENABLED is False. Skipping MAC change for monitor mode.")

    script_path = config.START_MON_SH_PATH
    try:
        cmd = [script_path, iface_to_mon]
        logger.info(f"Attempting to start monitor mode on {iface_to_mon} (current MAC may be spoofed). Executing: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)

        logger.debug(f"Monitor mode script stdout: {result.stdout}")
        if result.stderr:
            logger.warning(f"Monitor mode script stderr: {result.stderr}")

        # Verification step: check if monitor interface (e.g., wlan0mon) now exists and is in monitor mode
        monitor_interface_name = iface_to_mon + config.MONITOR_IFACE_SUFFIX # Common convention
        # Some scripts might create a different name or report the new name in stdout.
        # For robustness, one might parse result.stdout for the new interface name.
        # For now, assuming the conventional suffix.

        final_event_data = {
            "base_interface": iface_to_mon,
            "monitor_interface_expected": monitor_interface_name,
            "command": ' '.join(cmd),
            "script_rc": result.returncode,
            "script_output": result.stdout,
            "script_error": result.stderr
        }

        if result.returncode == 0:
            if interface_exists(monitor_interface_name) and is_monitor_mode(monitor_interface_name):
                logger.info(f"Successfully enabled monitor mode on {monitor_interface_name} (derived from {iface_to_mon}).")
                final_event_data.update({"success": True, "verified_monitor_interface": monitor_interface_name, "status_message": "Monitor mode enabled and verified."})
                log_event("monitor_mode_enabled", final_event_data)
                return jsonify({'status': 'success', 'message': f'Monitor mode enabled on {monitor_interface_name}.', 'output': result.stdout, 'error_output': result.stderr, "monitor_interface": monitor_interface_name}), 200
            else:
                logger.error(f"start-mon.sh script ran for {iface_to_mon} (RC:0), but expected monitor interface {monitor_interface_name} is not in monitor mode or does not exist.")
                final_event_data.update({"success": False, "status_message": "Script executed but monitor mode verification failed."})
                log_event("monitor_mode_failed_verification", final_event_data)
                return jsonify({'status': 'error', 'message': f"Failed to verify monitor mode on {monitor_interface_name} after script execution.", 'output': result.stdout, 'error_output': result.stderr}), 500
        else: # Script returned non-zero
            final_event_data.update({"success": False, "status_message": "start-mon.sh script failed."})
            log_event("monitor_mode_script_failed", final_event_data)
            return jsonify({'status': 'error', 'message': f"start-mon.sh script failed for {iface_to_mon}.", 'output': result.stdout, 'error_output': result.stderr, 'return_code': result.returncode}), 500

    except subprocess.CalledProcessError as e: # Should be caught if script fails and check=True (which it is)
        logger.error(f"Error starting monitor mode. Command: '{' '.join(e.cmd)}' failed with code {e.returncode}", exc_info=True)
        logger.error(f"stderr: {e.stderr}"); logger.error(f"stdout: {e.stdout}")
        log_event("monitor_mode_script_failed_exception", {"interface": iface_to_mon, "command": ' '.join(e.cmd), "success": False, "output": e.stdout, "error": e.stderr, "return_code": e.returncode})
        return jsonify({'status': 'error', 'message': e.stderr or "start-mon.sh execution failed.", 'output': e.stdout, 'command': e.cmd, 'return_code': e.returncode}), 500
    except subprocess.TimeoutExpired as e:
        logger.error(f"Timeout starting monitor mode on {iface_to_mon}. Command: '{' '.join(e.cmd)}'", exc_info=True)
        log_event("monitor_mode_script_timeout", {"interface": iface_to_mon, "command": ' '.join(e.cmd), "success": False, "error": "TimeoutExpired"})
        return jsonify({'status': 'error', 'message': f'Timeout starting monitor mode on {iface_to_mon}', 'command': e.cmd}), 500
    except FileNotFoundError:
        logger.error(f"Script {script_path} not found.", exc_info=True)
        log_event("monitor_mode_script_not_found", {"interface": iface_to_mon, "script_path": script_path, "success": False, "error": "FileNotFoundError"})
        return jsonify({'status': 'error', 'message': f'Script {script_path} not found. Ensure it is in the project root and executable.'}), 404
    except Exception as e: # Catch-all for other unexpected errors
        logger.exception(f"An unexpected error occurred while starting monitor mode on {iface_to_mon}")
        log_event("monitor_mode_unexpected_error", {"interface": iface_to_mon, "success": False, "error": str(e)})
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Endpoint: Start Scan
@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    data = request.json
    # Expects a monitor interface, e.g., wlan0mon.
    # The /api/monitor/start endpoint should have been called first to set this up.
    iface_to_use = data.get('interface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    duration = data.get('duration', "30") # Default duration 30 seconds, expect string from UI

    try:
        duration_seconds = int(duration)
    except ValueError:
        logger.warning(f"Invalid duration provided: '{duration}'. Defaulting to 30 seconds.")
        duration_seconds = 30

    if not iface_to_use: # Should not happen with default
        logger.error("No interface provided for scan.")
        return jsonify({'status': 'error', 'message': 'Interface not provided for scan.'}), 400

    logger.info(f"Scan request received for interface {iface_to_use} for {duration_seconds} seconds.")

    try:
        # Ensure the interface actually exists before trying to use it
        if not os.path.exists(f"/sys/class/net/{iface_to_use}"):
            logger.error(f"Scan requested on non-existent interface: {iface_to_use}. Please ensure it's in monitor mode.")
            return jsonify({'status': 'error', 'message': f"Interface {iface_to_use} does not exist. Is it in monitor mode?"}), 400

        scanner = AdaptiveScanner(interface=iface_to_use)
        # The scan_intensity parameter can be added to request data if needed in future
        scan_results = scanner.scan(duration_seconds=duration_seconds)

        # AdaptiveScanner.scan() returns a dict. If it contains an 'error' key, it indicates a failure within the scanner.
        if 'error' in scan_results:
            logger.error(f"AdaptiveScanner failed for interface {iface_to_use}: {scan_results['error']}")
            log_event("scan_failed", {"interface": iface_to_use, "duration": duration_seconds, "error": scan_results['error'], "details": scan_results})
            # Return a 500 error as the scan operation itself failed.
            return jsonify({"status": "error", "message": "Scan operation failed.", "details": scan_results['error']}), 500

        num_networks = len(scan_results.get('networks',[]))
        num_clients = len(scan_results.get('clients',[]))
        logger.info(f"Scan completed on {iface_to_use}. Found {num_networks} networks, {num_clients} clients.")
        log_event("scan_completed", {
            "interface": iface_to_use,
            "duration": duration_seconds,
            "network_count": num_networks,
            "client_count": num_clients,
            # "scan_results": scan_results # Optionally log full results if not too verbose for events
        })
        return jsonify(scan_results), 200

    except Exception as e: # Catch unexpected errors in the API endpoint logic itself
        logger.error(f"An unexpected server error occurred in /api/scan/start for interface {iface_to_use}: {e}", exc_info=True)
        log_event("scan_api_error", {"interface": iface_to_use, "duration": duration_seconds, "error": str(e)})
        return jsonify({'status': 'error', 'message': f"An unexpected server error occurred: {str(e)}"}), 500

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
    # Debug mode for Flask (and SocketIO) should ideally align with log level,
    # but Flask's debug is more about reloading and Werkzeug debugger.
    # Keeping INTRUDER_DEBUG for explicit Flask debug mode if needed.
    flask_debug_mode = os.environ.get('INTRUDER_DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting iNTRUDER server on port {port}")
    logger.info(f"Flask debug mode is {'ON' if flask_debug_mode else 'OFF'}")
    logger.info(f"Effective log level: {logging.getLevelName(root_logger.getEffectiveLevel())}")

    # When using eventlet or gevent, Flask's native debug mode (use_reloader=True) can cause issues.
    # SocketIO's run method handles this. If flask_debug_mode is True, it might enable reloader.
    # It's generally better to keep Flask's reloader off if using eventlet/gevent for SocketIO.
    logger.info("Validating configuration...")
    if not validate_config(config):
        logger.error("Critical configuration validation failed. Please check settings. Server will not start.")
        sys.exit(1) # Use sys.exit here
    else:
        logger.info("Configuration validation successful.")

    socketio.run(app, host='0.0.0.0', port=port, debug=flask_debug_mode, use_reloader=False)

# --- Configuration Validation Function ---
def validate_config(app_config):
    """
    Validates critical configuration settings at startup.
    Logs warnings or errors if issues are found.
    """
    val_logger = logging.getLogger(__name__ + ".config_validator") # Specific logger
    issues_found = 0
    warnings = []
    errors = []

    # 1. DEFAULT_WORDLIST
    default_wordlist = getattr(app_config, 'DEFAULT_WORDLIST', None)
    if default_wordlist: # Only validate if it's set
        if not os.path.exists(default_wordlist):
            warnings.append(f"DEFAULT_WORDLIST: Path '{default_wordlist}' does not exist.")
            issues_found +=1
        elif not os.access(default_wordlist, os.R_OK):
            warnings.append(f"DEFAULT_WORDLIST: Path '{default_wordlist}' is not readable.")
            issues_found +=1
        else:
            val_logger.debug(f"DEFAULT_WORDLIST ('{default_wordlist}') found and readable.")
    else:
        val_logger.info("DEFAULT_WORDLIST is not set. Users must provide a wordlist for cracking attempts.")

    # 2. EVENT_LOG_FILE
    event_log_path = getattr(app_config, 'EVENT_LOG_FILE', 'session_events.jsonl')
    event_log_abs_path = os.path.abspath(event_log_path)
    event_log_dir = os.path.dirname(event_log_abs_path)
    if os.path.exists(event_log_abs_path):
        if not os.access(event_log_abs_path, os.W_OK):
            errors.append(f"EVENT_LOG_FILE: Path '{event_log_abs_path}' exists but is not writable.")
            issues_found +=1
        else:
            val_logger.debug(f"EVENT_LOG_FILE ('{event_log_abs_path}') exists and is writable.")
    else: # File doesn't exist, check directory writability
        if not os.path.exists(event_log_dir):
             # Attempt to create if not exists (if it's within project, might be fine)
            try:
                os.makedirs(event_log_dir, exist_ok=True)
                val_logger.info(f"Created directory for EVENT_LOG_FILE: {event_log_dir}")
                if not os.access(event_log_dir, os.W_OK): # Check again after creation
                    errors.append(f"EVENT_LOG_FILE: Directory '{event_log_dir}' created but is not writable.")
                    issues_found +=1
            except Exception as e_mkdir:
                errors.append(f"EVENT_LOG_FILE: Directory '{event_log_dir}' does not exist and could not be created: {e_mkdir}")
                issues_found +=1
        elif not os.access(event_log_dir, os.W_OK):
            errors.append(f"EVENT_LOG_FILE: Directory '{event_log_dir}' for '{event_log_abs_path}' is not writable.")
            issues_found +=1
        else:
             val_logger.debug(f"EVENT_LOG_FILE directory ('{event_log_dir}') is writable for new file '{event_log_abs_path}'.")


    # 3. REPORTS_DIR
    reports_dir_path = getattr(app_config, 'REPORTS_DIR', 'reports')
    reports_dir_abs_path = os.path.abspath(reports_dir_path)
    # ReportGenerator.__init__ already tries to create this. Here we primarily check.
    if os.path.exists(reports_dir_abs_path):
        if not os.access(reports_dir_abs_path, os.W_OK) or not os.access(reports_dir_abs_path, os.X_OK): # Need write and execute (for listing)
            errors.append(f"REPORTS_DIR: Path '{reports_dir_abs_path}' exists but is not writable/browsable.")
            issues_found +=1
        else:
            val_logger.debug(f"REPORTS_DIR ('{reports_dir_abs_path}') exists and is accessible.")
    else:
        # Check if parent is writable to allow ReportGenerator to create it
        parent_reports_dir = os.path.dirname(reports_dir_abs_path)
        if not os.path.exists(parent_reports_dir):
             errors.append(f"REPORTS_DIR: Parent directory '{parent_reports_dir}' for '{reports_dir_abs_path}' does not exist.")
             issues_found +=1
        elif not os.access(parent_reports_dir, os.W_OK):
            errors.append(f"REPORTS_DIR: Parent directory '{parent_reports_dir}' for '{reports_dir_abs_path}' is not writable. Directory creation by ReportGenerator might fail.")
            issues_found +=1
        else:
            val_logger.info(f"REPORTS_DIR ('{reports_dir_abs_path}') does not exist but parent is writable. ReportGenerator should create it.")


    # 4. Script Paths
    scripts_to_check = {
        "START_MON_SH_PATH": getattr(app_config, 'START_MON_SH_PATH', './start-mon.sh'),
        # SCAN_SH_PATH is no longer primary, but if it were:
        # "SCAN_SH_PATH": getattr(app_config, 'SCAN_SH_PATH', './scan.sh'),
    }
    for name, path in scripts_to_check.items():
        if path: # Only validate if path is set
            script_abs_path = os.path.abspath(path)
            if not os.path.exists(script_abs_path):
                warnings.append(f"{name}: Script path '{script_abs_path}' (from '{path}') does not exist.")
                issues_found +=1
            elif not os.access(script_abs_path, os.X_OK):
                warnings.append(f"{name}: Script '{script_abs_path}' (from '{path}') is not executable.")
                issues_found +=1
            else:
                val_logger.debug(f"{name} ('{script_abs_path}') found and executable.")
        else:
             val_logger.debug(f"{name} is not configured.")


    # 5. LOG_LEVEL
    log_level_str = getattr(app_config, 'LOG_LEVEL', 'INFO').upper()
    numeric_config_level = getattr(logging, log_level_str, None)
    if not isinstance(numeric_config_level, int):
        warnings.append(f"LOG_LEVEL: Value '{app_config.LOG_LEVEL}' is invalid. Defaulting to INFO.")
        # This issue is already handled by the root logger setup, this is just an explicit startup warning.
        issues_found +=1
    else:
        val_logger.debug(f"LOG_LEVEL ('{log_level_str}') is valid.")

    # Summary
    if errors: # Prioritize showing errors
        for error_msg in errors:
            val_logger.error(f"Configuration Error: {error_msg}")
    if warnings:
        for warning_msg in warnings:
            val_logger.warning(f"Configuration Warning: {warning_msg}")

    if issues_found == 0:
        val_logger.info("Configuration validation successful. All critical settings appear valid.")
    else:
        val_logger.warning(f"Configuration validation complete. Issues found: {issues_found} (see warnings/errors above).")

    return not errors # Return True if no hard errors, False otherwise

# --- Reporting Endpoint ---
@app.route('/api/reporting/generate', methods=['POST']) # Using POST for an action that creates resources (reports)
def api_generate_reports():
    logger.info("Report generation requested via API.")
    log_event("report_generation_requested", {"formats_requested": ["json", "markdown"], "triggered_by": "api"})

    report_generator = ReportGenerator() # Uses config for event_log_file and reports_dir by default

    # Generate JSON report
    json_report_path = report_generator.generate_json_report()
    if json_report_path:
        logger.info(f"JSON report generated: {json_report_path}")
    else:
        logger.warning("JSON report generation failed or no events to report.")

    # Generate Markdown report
    md_report_path = report_generator.generate_markdown_report()
    if md_report_path:
        logger.info(f"Markdown report generated: {md_report_path}")
    else:
        logger.warning("Markdown report generation failed or no events to report.")

    success = bool(json_report_path or md_report_path) # Considered success if at least one report is made

    response_data = {
        "status": "success" if success else "no_events_or_failure",
        "message": "Report generation process completed." if success else "No events to report or report generation failed for all formats.",
        "json_report_path": json_report_path,
        "markdown_report_path": md_report_path
    }

    log_event("report_generation_completed", {
        "success": success,
        "json_report_generated": bool(json_report_path),
        "markdown_report_generated": bool(md_report_path),
        "json_report_path": json_report_path, # Path might be None
        "markdown_report_path": md_report_path # Path might be None
    })

    return jsonify(response_data), 200 # Return 200, status in JSON indicates outcome
