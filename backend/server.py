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
import re # For basic MAC/interface validation
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO
from typing import Optional, List, Dict, Any # Updated List, Dict, Any
from datetime import datetime, timezone # Added datetime, timezone

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
    # Ensure log directory exists before attempting to create file handler
    log_file_dir = os.path.dirname(config.LOG_FILE)
    if log_file_dir and not os.path.exists(log_file_dir):
        os.makedirs(log_file_dir, exist_ok=True)
        root_logger.info(f"Created log directory: {log_file_dir}")

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
# MITM Plugin has been removed.

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
# Serve static files from ../frontend/static and templates from ../frontend
app = Flask(__name__, static_folder='../frontend/static', template_folder='../frontend')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Route to serve index.html from the frontend directory
@app.route('/')
def serve_index():
    return render_template("index.html")

# Global process/state holders
_services: Dict[str, Any] = {} # Added type hint
handshake_capture_log: List[Dict[str, Any]] = [] # For storing info about successful handshake captures

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
    # os._exit(0) is a very forceful way to exit, bypassing standard cleanup (e.g. finally blocks).
    # For eventlet/gevent with Flask-SocketIO, a clean shutdown can be tricky.
    # A more graceful approach might involve socketio.stop() if it were available,
    # or raising SystemExit, but os._exit is often used when other methods fail to terminate all threads/greenlets.
    # TODO: Research best practice for graceful shutdown of Flask-SocketIO with eventlet,
    # especially if background tasks managed by SocketIO need cleanup.
    os._exit(0) # Forcing exit, as some subprocesses or threads might hang

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

# Endpoint: Start Rogue AP
@app.route('/api/rogue_ap/start', methods=['POST'])
def api_start_rogue_ap():
    data = request.json
    iface = data.get('iface') # AP interface
    ssid = data.get('ssid')
    wan_iface = data.get('wan_iface', getattr(config, 'DEFAULT_WAN_IFACE', 'eth0')) # WAN interface from config or 'eth0'

    # Validate channel input
    try:
        # Ensure channel is int, default to 6 if not provided or invalid
        channel = int(data.get('channel', 6))
        if not (1 <= channel <= 14): # Basic Wi-Fi channel validation (2.4GHz)
            logger.warning(f"Invalid channel value {channel} received for Rogue AP. Defaulting to 6.")
            channel = 6
    except (ValueError, TypeError):
        logger.warning(f"Invalid channel value type received: {data.get('channel')}. Defaulting to 6 for Rogue AP.")
        channel = 6

    # Basic validation for required string parameters
    if not (iface and isinstance(iface, str) and ssid and isinstance(ssid, str)):
        logger.error(f"Missing or invalid 'iface' or 'ssid' for Rogue AP. Got iface: '{iface}', ssid: '{ssid}'")
        return jsonify({"status": "error", "message": "Missing or invalid parameters: 'iface' (string) and 'ssid' (string) are required."}), 400
    if not (wan_iface and isinstance(wan_iface, str)): # wan_iface must also be a valid non-empty string
        logger.error(f"Invalid 'wan_iface' for Rogue AP: '{wan_iface}'")
        return jsonify({"status": "error", "message": "Invalid or missing 'wan_iface' parameter (string required)."}), 400
    # TODO: Add more specific validation for iface names if needed (e.g., regex for valid characters/length)

    # For consistency, let's add an API-level event.
    log_event("rogue_ap_api_start_requested", {"ap_interface": iface, "wan_interface": wan_iface, "ssid": ssid, "channel": channel})

    ap = RogueAP(iface=iface, ssid=ssid, channel=channel, wan_iface=wan_iface)
    # RogueAP.start_services() itself logs detailed events like "rogue_ap_started"
    success = ap.start_services()
    if success:
        _services['rogue_ap'] = ap
        # Assuming procs might be an attribute or part of a status method if needed by caller
        return jsonify({'status': 'Rogue AP services starting...'}), 200
    else:
        # start_services should log its own failure details.
        return jsonify({'status': 'error', 'message': 'Failed to start all Rogue AP services. Check server logs.'}), 500


# Endpoint: Stop Rogue AP
@app.route('/api/rogue_ap/stop', methods=['POST'])
def api_stop_rogue_ap():
    ap = _services.pop('rogue_ap', None)
    if not ap:
        return jsonify({"status": "error", 'message': 'Rogue AP not running or already stopped'}), 400

    log_event("rogue_ap_api_stop_requested", {"interface": getattr(ap, 'iface', 'unknown'), "ssid": getattr(ap, 'ssid', 'unknown')})
    ap.cleanup() # This logs "rogue_ap_cleanup_finished"
    return jsonify({'status': 'stopped', 'message': 'Rogue AP services are being cleaned up.'}), 200

# MITM Plugin and its routes have been removed.


# Endpoint: Start WPS Attack
@app.route('/api/wps/start', methods=['POST'])
def api_start_wps():
    data = request.json
    iface = data.get('iface') # Monitor interface for Reaver
    bssid = data.get('bssid') # Target BSSID

    # Validate timeout
    try:
        # Use a shorter default for API calls than the class default if appropriate, or config.
        timeout_val = int(data.get('timeout', getattr(config, 'REAVER_API_TIMEOUT', 3600)))
        if timeout_val <= 0:
             logger.warning(f"Non-positive timeout value {timeout_val} received for WPS attack. Using default 3600s.")
             timeout_val = 3600
    except (ValueError, TypeError):
        logger.warning(f"Invalid timeout value type received for WPS attack: {data.get('timeout')}. Defaulting to 3600s.")
        timeout_val = 3600

    # Validate channel (optional for Reaver, but good to pass if known)
    raw_channel = data.get('channel')
    channel_val: Optional[int] = None
    if raw_channel is not None and str(raw_channel).strip() != '': # Allow empty string to mean None
        try:
            channel_val = int(raw_channel)
            # Reaver often supports channels 1-14 for 2.4GHz, and higher for 5GHz.
            # A simple check for positive integer here. Reaver will validate specific channel capabilities.
            if not (1 <= channel_val <= 165):
                logger.warning(f"Channel value {channel_val} for WPS attack is outside typical Wi-Fi range. Letting Reaver handle/validate.")
                # Keep it if user insists, Reaver might have specific interpretations or fail.
        except (ValueError, TypeError):
            logger.warning(f"Invalid channel value type received for WPS attack: '{raw_channel}'. Letting Reaver auto-detect.")
            channel_val = None # Let Reaver auto-detect

    # additional_options is for passing things like --pixie-dust, etc.
    additional_options = data.get('additional_options')
    if additional_options and not (isinstance(additional_options, list) and all(isinstance(opt, str) for opt in additional_options)):
        return jsonify({"status": "error", "message": "'additional_options' must be a list of strings."}), 400

    if not (iface and isinstance(iface, str) and bssid and isinstance(bssid, str)):
        return jsonify({"status": "error", "message": "Missing or invalid parameters: 'iface' (string) and 'bssid' (string) are required."}), 400
    if not (len(bssid) == 17 and re.match(r"([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})", bssid)):
         return jsonify({'status': 'error', 'message': 'Invalid BSSID format. Expected XX:XX:XX:XX:XX:XX'}), 400

    wps_instance = WPSAttack(iface=iface, target_bssid=bssid, channel=channel_val)
    _services['wps'] = wps_instance # Store for potential shutdown

    wps_attack_result = wps_instance.run(timeout=timeout_val, additional_options=additional_options)
    # Event logging for WPS attack start/stop/results is handled within WPSAttack class itself.

    # Determine HTTP status code based on outcome
    http_status_code = 500 # Default to server error
    status_from_run = wps_attack_result.get('status', 'error')
    if status_from_run in ['success_psk_found', 'success_pin_found', 'completed_no_key']:
        http_status_code = 200
    elif status_from_run == 'timeout':
        http_status_code = 408 # Request Timeout
    elif status_from_run == 'error' and "not found" in wps_attack_result.get('message','').lower(): # Tool not found
        http_status_code = 404
    elif status_from_run == 'error' and ("interface" in wps_attack_result.get('message','').lower() or "bssid" in wps_attack_result.get('message','').lower()):
        http_status_code = 400 # Bad request (e.g. bad interface or BSSID format)

    return jsonify(wps_attack_result), http_status_code

# Endpoint: Deauthentication Attack
@app.route('/api/deauth/start', methods=['POST'])
def api_start_deauth():
    data = request.json
    iface = data.get('iface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    target_bssid = data.get('target_bssid', data.get('target'))
    client_mac = data.get('client_mac', 'FF:FF:FF:FF:FF:FF') # Default to broadcast.

    try:
        count_val = int(data.get('count', 10))
        if count_val < 0:
            logger.warning(f"Invalid deauth count '{data.get('count')}' received. Using default 10.")
            count_val = 10
    except (ValueError, TypeError):
        logger.warning(f"Invalid deauth count type '{data.get('count')}' received. Using default 10.")
        count_val = 10

    # Validate required parameters
    if not (target_bssid and isinstance(target_bssid, str) and len(target_bssid) == 17 and re.match(r"([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})", target_bssid)):
        return jsonify({'status': 'error', 'message': 'Valid Target BSSID (target_bssid) in XX:XX:XX:XX:XX:XX format is required.'}), 400
    if not (iface and isinstance(iface, str)):
        return jsonify({'status': 'error', 'message': 'Valid interface name (iface) is required.'}), 400
    if not (isinstance(client_mac, str) and len(client_mac) == 17 and re.match(r"([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})", client_mac, re.IGNORECASE)): # client_mac can be FF:FF..
         return jsonify({'status': 'error', 'message': 'Invalid client_mac format. Expected XX:XX:XX:XX:XX:XX or FF:FF:FF:FF:FF:FF for broadcast.'}), 400

    log_event("deauth_attack_api_requested", {
        "interface": iface, "target_bssid": target_bssid,
        "client_mac_requested": client_mac, "count_requested": count_val
    })

    deauth_instance = DeauthAttack(iface=iface, target_mac=target_bssid, count=count_val)
    _services['deauth'] = deauth_instance

    deauth_result = deauth_instance.run()

    http_status_code = 500
    status_from_run = deauth_result.get('status', 'error')

    if status_from_run == 'success':
        http_status_code = 200
    elif status_from_run == 'error':
        msg_lower = deauth_result.get('message', '').lower()
        if "not found" in msg_lower:
            http_status_code = 404
        elif "interface" in msg_lower and ("exist" in msg_lower or "disappeared" in msg_lower or "monitor mode" in msg_lower):
            http_status_code = 400

    return jsonify(deauth_result), http_status_code

# Endpoint: Capture Handshake
@app.route('/api/handshake/start', methods=['POST'])
def api_start_handshake():
    data = request.json
    iface = data.get('iface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    ssid = data.get('ssid')
    bssid = data.get('bssid')

    raw_channel = data.get('channel')
    channel_val: Optional[int] = None
    if raw_channel is not None and str(raw_channel).strip() != '':
        try:
            channel_val = int(raw_channel)
            if not (0 <= channel_val <= 165):
                logger.warning(f"Invalid channel value {channel_val} for handshake capture. Letting airodump-ng auto-detect or use its default.")
                channel_val = None
        except (ValueError, TypeError):
            logger.warning(f"Invalid channel value type received for handshake capture: '{raw_channel}'. Letting airodump-ng auto-detect.")
            channel_val = None

    # Validate required parameters
    if not (iface and isinstance(iface, str)):
         return jsonify({'status': 'error', 'message': 'Valid interface name (iface) is required.'}), 400
    if not ssid and not bssid:
        return jsonify({'status': 'error', 'message': 'Either SSID (ssid) or Target BSSID (bssid) must be provided for handshake capture.'}), 400
    if bssid and not (isinstance(bssid, str) and len(bssid) == 17 and re.match(r"([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})", bssid)):
        return jsonify({'status': 'error', 'message': 'Invalid BSSID format. Expected XX:XX:XX:XX:XX:XX'}), 400
    if ssid and not isinstance(ssid, str):
         return jsonify({'status': 'error', 'message': 'Invalid SSID format. Expected a string.'}), 400
    # TODO: Add regex validation for BSSID format and potentially for SSID (e.g. length, allowed characters).

    log_event("handshake_capture_api_requested", {"interface": iface, "ssid": ssid, "bssid": bssid, "channel_requested": channel_val})

    hs_capture_instance = HandshakeCapture(iface=iface, ssid=ssid, bssid=bssid, channel=channel_val)
    _services['handshake'] = hs_capture_instance

    capture_result = hs_capture_instance.capture()

    if capture_result.get("status") in ["success", "success_with_errors"] and capture_result.get("file"):
        handshake_capture_log.append({
            "file": capture_result.get("file"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "bssid": bssid, # From request
            "ssid": ssid    # From request
        })
        log_event("handshake_logged_for_stats", {"file": capture_result.get("file"), "bssid": bssid, "ssid": ssid})

    http_status_code = 500
    status_from_run = capture_result.get("status", "error")

    if status_from_run in ["success", "success_with_errors"]:
        http_status_code = 200
    elif status_from_run == "error":
        msg_lower = capture_result.get("message", "").lower()
        if "not found" in msg_lower:
            http_status_code = 404
        elif "interface" in msg_lower and "exist" in msg_lower:
            http_status_code = 400

    return jsonify(capture_result), http_status_code

# Endpoint: Stop Handshake Capture
@app.route('/api/handshake/stop', methods=['POST'])
def api_stop_handshake():
    logger.info("Handshake stop requested via API.")
    hs_instance = _services.pop('handshake', None) # Remove from services once stop is called
    if hs_instance and hasattr(hs_instance, 'shutdown'):
        try:
            hs_instance.shutdown() # shutdown() in HandshakeCapture logs events
            logger.info("Handshake capture process instructed to stop.")
            return jsonify({"status": "success", "message": "Handshake capture stop initiated."}), 200
        except Exception as e:
            logger.error(f"Error during handshake stop: {e}", exc_info=True)
            return jsonify({"status": "error", "message": f"Error stopping handshake: {str(e)}"}), 500
    else:
        logger.warning("No active handshake capture found to stop.")
        return jsonify({"status": "error", "message": "No active handshake capture found or already stopped."}), 404

# Endpoint: Wi-Fi Cracking
@app.route('/api/crack/start', methods=['POST'])
def api_start_crack():
    data = request.json
    handshake_file = data.get('handshake_file')
    wordlist_from_request = data.get('wordlist')
    bssid_from_request = data.get('bssid') # Optional BSSID for aircrack-ng
    wordlist_to_use = None

    if not (handshake_file and isinstance(handshake_file, str)):
        return jsonify({'status': 'error', 'message': 'Handshake file path (handshake_file) is required as a string.'}), 400
    # TODO: Add validation to check if handshake_file path seems plausible or exists, though backend module also checks.

    if wordlist_from_request:
        if not isinstance(wordlist_from_request, str):
            return jsonify({'status': 'error', 'message': 'Wordlist path (wordlist) must be a string.'}), 400
        wordlist_to_use = wordlist_from_request
        logger.info(f"Using wordlist from request: {wordlist_to_use}")
    elif getattr(config, 'DEFAULT_WORDLIST', None):
        wordlist_to_use = config.DEFAULT_WORDLIST
        logger.info(f"Using DEFAULT_WORDLIST from config: {wordlist_to_use}")
        if not os.path.exists(wordlist_to_use) or not os.access(wordlist_to_use, os.R_OK):
            msg = f"DEFAULT_WORDLIST '{wordlist_to_use}' is configured but not found or not readable."
            logger.error(msg)
            log_event("crack_attempt_failed", {"handshake_file": handshake_file, "reason": "Default wordlist invalid", "default_wordlist_path": wordlist_to_use})
            return jsonify({"status": "error", "message": msg}), 500
    else:
        msg = "Wordlist not provided in request and no DEFAULT_WORDLIST is configured."
        logger.warning(msg)
        log_event("crack_attempt_failed", {"handshake_file": handshake_file, "reason": "No wordlist provided or configured"})
        return jsonify({"status": "error", "message": msg}), 400

    if bssid_from_request and not (isinstance(bssid_from_request, str) and len(bssid_from_request) == 17 and re.match(r"([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})", bssid_from_request)):
        return jsonify({'status': 'error', 'message': 'Invalid BSSID format for cracking. Expected XX:XX:XX:XX:XX:XX'}), 400

    # WifiCracker's __init__ now takes bssid.
    cracker = WifiCracker(handshake_file=handshake_file, wordlist=wordlist_to_use, bssid=bssid_from_request)
    _services['cracker'] = cracker # Store for potential shutdown, though cracking is usually blocking

    crack_result = cracker.run()
    # Event logging is handled within WifiCracker.run()

    http_status_code = 500 # Default
    status_from_run = crack_result.get('status', 'error')
    if status_from_run in ['success', 'failed']: # 'failed' means aircrack ran but no key found
        http_status_code = 200
    elif status_from_run == 'error':
        if "not found" in crack_result.get('message','').lower(): # Tool not found
            http_status_code = 404

    return jsonify(crack_result), http_status_code

# Endpoint: Start Monitor Mode
@app.route('/api/monitor/start', methods=['POST'])
def api_start_monitor():
    data = request.json
    iface_to_mon = data.get('iface', config.DEFAULT_IFACE)

    # Basic validation for interface name format
    # Regex for typical interface names (alphanumeric, can include 'mon', '.', '-', '_')
    # This is a basic sanity check; underlying tools will do more specific validation.
    if not (isinstance(iface_to_mon, str) and iface_to_mon and re.match(r"^[a-zA-Z0-9\._-]+$", iface_to_mon) and len(iface_to_mon) < 20):
        logger.error(f"Invalid base interface name provided for monitor mode: '{iface_to_mon}'")
        return jsonify({"status": "error", "message": f"Invalid or missing interface name: '{iface_to_mon}'."}), 400

    if not interface_exists(iface_to_mon):
        msg = f"Base interface '{iface_to_mon}' not found. Cannot start monitor mode."
        logger.error(msg)
        log_event("monitor_mode_failed", {"interface": iface_to_mon, "reason": "Base interface not found"})
        return jsonify({"status": "error", "message": msg}), 400

    # TODO: Centralize MAC changing logic. Currently, MACChanger is also used within some plugin classes (e.g., AdaptiveScanner, DeauthAttack).
    # A decision should be made whether MAC changes are primarily an API-level concern before calling a plugin,
    # or if plugins should manage their own OpSec internally. For monitor mode, changing the MAC of the *base* interface
    # before `airmon-ng start` might be desired. `start-mon.sh` itself doesn't currently handle MAC changing.

    mac_change_enabled_runtime = getattr(config, 'MAC_CHANGE_ENABLED', False)
    if mac_change_enabled_runtime:
        logger.info(f"MAC_CHANGE_ENABLED is True. Attempting to change MAC for '{iface_to_mon}' before starting monitor mode.")
        mac_changer = MACChanger()
        if mac_changer.macchanger_path:
            original_mac = mac_changer.get_current_mac(iface_to_mon)
            if original_mac:
                logger.info(f"Original MAC for '{iface_to_mon}': {original_mac}")
                new_mac, _ = mac_changer.set_mac_random(iface_to_mon) # This logs events within MACChanger
                if new_mac and new_mac.lower() != original_mac.lower():
                    logger.info(f"Successfully set random MAC for '{iface_to_mon}' to '{new_mac}' before monitor mode start.")
                elif new_mac:
                    logger.info(f"MAC for '{iface_to_mon}' is '{new_mac}' (may not have changed if already random). Proceeding.")
                else:
                    logger.warning(f"Failed to set random MAC for '{iface_to_mon}'. Proceeding with current/original MAC: {original_mac}.")
            else:
                logger.warning(f"Could not get original MAC for '{iface_to_mon}'. Skipping MAC change before monitor mode.")
        else:
            logger.warning("MACChanger utility is not available (macchanger command not found by MACChanger class). Skipping MAC change for monitor mode.")
    else:
        logger.info("MAC_CHANGE_ENABLED is False. Skipping MAC change before starting monitor mode.")

    script_path = getattr(config, 'START_MON_SH_PATH', './start-mon.sh')
    try:
        cmd = [script_path, iface_to_mon]
        logger.info(f"Attempting to start monitor mode on '{iface_to_mon}' (current MAC may be spoofed). Executing: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)

        logger.debug(f"Monitor mode script stdout: {result.stdout.strip() if result.stdout else '<empty>'}")
        if result.stderr:
            logger.warning(f"Monitor mode script stderr: {result.stderr.strip()}")

        # start-mon.sh should ideally output the name of the monitor interface created.
        # For now, we assume a convention or let the client infer.
        # A more robust solution would be for start-mon.sh to echo the new interface name as its last line.
        monitor_interface_name_from_script = result.stdout.strip().splitlines()[-1] if result.stdout else ""
        # Basic check if the output looks like an interface name
        if not (monitor_interface_name_from_script and re.match(r"^[a-zA-Z0-9\._-]+$", monitor_interface_name_from_script) and len(monitor_interface_name_from_script) < 20):
            monitor_interface_name_from_script = f"{iface_to_mon}{config.MONITOR_IFACE_SUFFIX}" # Fallback to convention
            logger.warning(f"Could not parse monitor interface name from script output. Assuming conventional name: {monitor_interface_name_from_script}")
        else:
            logger.info(f"Monitor interface name reported by script: {monitor_interface_name_from_script}")


        final_event_data = {
            "base_interface": iface_to_mon,
            "monitor_interface_reported_by_script": monitor_interface_name_from_script,
            "command": ' '.join(cmd),
            "script_rc": result.returncode,
            "script_output": result.stdout,
            "script_error": result.stderr
        }

        if result.returncode == 0:
            # Verify the reported/assumed monitor interface
            if interface_exists(monitor_interface_name_from_script) and is_monitor_mode(monitor_interface_name_from_script):
                logger.info(f"Successfully enabled and verified monitor mode on '{monitor_interface_name_from_script}' (derived from '{iface_to_mon}').")
                final_event_data.update({"success": True, "verified_monitor_interface": monitor_interface_name_from_script, "status_message": "Monitor mode enabled and verified."})
                log_event("monitor_mode_enabled", final_event_data)
                return jsonify({'status': 'success', 'message': f'Monitor mode enabled on {monitor_interface_name_from_script}.', 'output': result.stdout, 'error_output': result.stderr, "monitor_interface": monitor_interface_name_from_script}), 200
            else:
                logger.error(f"start-mon.sh script ran for '{iface_to_mon}' (RC:0), but reported/expected monitor interface '{monitor_interface_name_from_script}' is not in monitor mode or does not exist.")
                final_event_data.update({"success": False, "status_message": "Script executed but monitor mode verification failed."})
                log_event("monitor_mode_failed_verification", final_event_data)
                return jsonify({'status': 'error', 'message': f"Failed to verify monitor mode on '{monitor_interface_name_from_script}' after script execution.", 'output': result.stdout, 'error_output': result.stderr}), 500
        else: # Script returned non-zero (should be caught by check=True, but as fallback)
            final_event_data.update({"success": False, "status_message": "start-mon.sh script failed."})
            log_event("monitor_mode_script_failed", final_event_data)
            return jsonify({'status': 'error', 'message': f"start-mon.sh script failed for '{iface_to_mon}'.", 'output': result.stdout, 'error_output': result.stderr, 'return_code': result.returncode}), 500

    except subprocess.CalledProcessError as e:
        logger.error(f"Error starting monitor mode. Command: '{' '.join(e.cmd)}' failed with code {e.returncode}", exc_info=True)
        log_event("monitor_mode_script_failed_exception", {"interface": iface_to_mon, "command": ' '.join(e.cmd), "success": False, "output": e.stdout or "", "error": e.stderr or "", "return_code": e.returncode})
        return jsonify({'status': 'error', 'message': e.stderr or "start-mon.sh execution failed.", 'output': e.stdout or "", 'command': e.cmd, 'return_code': e.returncode}), 500
    except subprocess.TimeoutExpired as e:
        logger.error(f"Timeout starting monitor mode on '{iface_to_mon}'. Command: '{' '.join(e.cmd)}'", exc_info=True)
        log_event("monitor_mode_script_timeout", {"interface": iface_to_mon, "command": ' '.join(e.cmd), "success": False, "error": "TimeoutExpired"})
        return jsonify({'status': 'error', 'message': f'Timeout starting monitor mode on {iface_to_mon}', 'command': e.cmd}), 500
    except FileNotFoundError:
        logger.error(f"Script '{script_path}' not found.", exc_info=True)
        log_event("monitor_mode_script_not_found", {"interface": iface_to_mon, "script_path": script_path, "success": False, "error": "FileNotFoundError"})
        return jsonify({'status': 'error', 'message': f'Script {script_path} not found. Ensure it is correctly configured and executable.'}), 404
    except Exception as e:
        logger.exception(f"An unexpected error occurred while starting monitor mode on '{iface_to_mon}'")
        log_event("monitor_mode_unexpected_error", {"interface": iface_to_mon, "success": False, "error": str(e), "exception_type": type(e).__name__})
        return jsonify({'status': 'error', 'message': f"An unexpected error occurred: {str(e)}"}), 500

# Endpoint: Start Scan
@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    data = request.json
    iface_to_use = data.get('interface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    duration_str = data.get('duration', "30") # Default duration 30 seconds

    # Validate duration
    try:
        duration_seconds = int(duration_str)
        if duration_seconds <= 0:
            logger.warning(f"Non-positive duration provided for scan: '{duration_str}'. Using default 30 seconds.")
            duration_seconds = 30
    except (ValueError, TypeError): # Catch if 'duration' is not a valid integer string
        logger.warning(f"Invalid duration value type received for scan: '{duration_str}'. Defaulting to 30 seconds.")
        duration_seconds = 30

    if not (isinstance(iface_to_use, str) and iface_to_use): # Basic check for non-empty string
        logger.error("No interface or invalid interface name provided for scan.")
        return jsonify({'status': 'error', 'message': 'Valid interface name not provided for scan.'}), 400
    # TODO: Add more specific validation for monitor interface name format if needed.

    logger.info(f"Scan request received for interface '{iface_to_use}' for {duration_seconds} seconds.")

    try:
        scanner = AdaptiveScanner(interface=iface_to_use)
        scan_results = scanner.scan(duration_seconds=duration_seconds) # scan_intensity is a placeholder in AdaptiveScanner for now

        if scan_results.get("error"):
            logger.error(f"AdaptiveScanner reported an error for interface '{iface_to_use}': {scan_results['error']}")
            http_status_code = 500
            error_msg_lower = scan_results['error'].lower()
            if "not found" in error_msg_lower:
                http_status_code = 404
            elif "interface" in error_msg_lower and "exist" in error_msg_lower:
                 http_status_code = 400
            elif "monitor mode" in error_msg_lower:
                 http_status_code = 400
            return jsonify(scan_results), http_status_code

        num_networks = len(scan_results.get('networks', []))
        num_clients = len(scan_results.get('clients', []))
        logger.info(f"Scan completed on '{iface_to_use}'. Found {num_networks} networks, {num_clients} clients.")
        return jsonify(scan_results), 200

    except Exception as e:
        logger.error(f"An unexpected server error occurred in /api/scan/start for interface '{iface_to_use}': {e}", exc_info=True)
        log_event("scan_api_error", {"interface": iface_to_use, "duration_requested": duration_seconds, "error": str(e), "exception_type": type(e).__name__})
        return jsonify({'status': 'error', 'message': f"An unexpected server error occurred: {str(e)}"}), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200

# Endpoint to get the default monitor interface
@app.route('/api/interfaces/default_monitor', methods=['GET'])
def get_default_monitor_interface():
    # This is a simplified version; a more robust way would track active monitor iface
    # or verify existence and mode.
    default_base_iface = getattr(config, 'DEFAULT_IFACE', 'wlan0')
    monitor_suffix = getattr(config, 'MONITOR_IFACE_SUFFIX', 'mon')
    mon_iface = f"{default_base_iface}{monitor_suffix}"

    # Optionally, verify if this interface actually exists and is in monitor mode here
    # For now, just returning the configured default convention.
    # exists = interface_exists(mon_iface)
    # is_mon = is_monitor_mode(mon_iface)
    # current_status_str = "active" if exists and is_mon else ("exists" if exists else "not_found")

    log_event("default_monitor_interface_queried", {"interface": mon_iface, "source": "config_defaults"})
    return jsonify({"status": "success", "interface": mon_iface}), 200

# Endpoint to get handshake capture stats
@app.route('/api/stats/handshakes_count', methods=['GET'])
def get_handshakes_count():
    count = len(handshake_capture_log)
    last_capture_time = None
    if handshake_capture_log:
        last_capture_time = handshake_capture_log[-1]["timestamp"]
    # Client side can format the timestamp.
    return jsonify({"status": "success", "count": count, "last_capture_timestamp": last_capture_time}), 200

# Endpoint to check root status
@app.route('/api/system/root_status', methods=['GET'])
def get_root_status():
    is_root = (os.geteuid() == 0)
    log_event("root_status_queried", {"is_root": is_root})
    return jsonify({"status": "success", "is_root": is_root}), 200

# SocketIO example: real-time logs
@socketio.on('connect')
def on_connect():
    logger.info('Dashboard client connected')
    socketio.emit('status', {'services': list(_services.keys())})

if __name__ == '__main__':
    port = int(os.environ.get('INTRUDER_PORT', 5000))
    flask_debug_mode = os.environ.get('INTRUDER_DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting iNTRUDER server on port {port}")
    logger.info(f"Flask debug mode is {'ON' if flask_debug_mode else 'OFF'}")
    logger.info(f"Effective log level: {logging.getLevelName(root_logger.getEffectiveLevel())}")

    # Validate configuration before running the server
    if not validate_config(config): # Call validate_config here
        logger.critical("Critical configuration validation errors found. Server will not start.")
        sys.exit(1) # Exit if critical errors in config (e.g., unwritable log dirs)

    socketio.run(app, host='0.0.0.0', port=port, debug=flask_debug_mode, use_reloader=False)

# --- Configuration Validation Function ---
# (Keep validate_config function as it was, it's mostly fine)
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
        # Path is now constructed with APP_BASE_DIR in config.py
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

    # 2. EVENT_LOG_FILE and LOG_FILE directory writability
    log_paths_to_check = {
        "EVENT_LOG_FILE": getattr(app_config, 'EVENT_LOG_FILE', os.path.join(config.APP_BASE_DIR, 'logs', 'session_events.jsonl')),
        "LOG_FILE": getattr(app_config, 'LOG_FILE', os.path.join(config.APP_BASE_DIR, 'logs', 'intruder.log'))
    }
    for name, path in log_paths_to_check.items():
        log_abs_path = os.path.abspath(path)
        log_dir = os.path.dirname(log_abs_path)
        if os.path.exists(log_abs_path):
            if not os.access(log_abs_path, os.W_OK):
                errors.append(f"{name}: Path '{log_abs_path}' exists but is not writable.")
                issues_found +=1
            else:
                val_logger.debug(f"{name} ('{log_abs_path}') exists and is writable.")
        else: # File doesn't exist, check directory writability
            if not os.path.exists(log_dir):
                try: # Attempt to create if not exists
                    os.makedirs(log_dir, exist_ok=True)
                    val_logger.info(f"Created directory for {name}: {log_dir}")
                    if not os.access(log_dir, os.W_OK):
                        errors.append(f"{name}: Directory '{log_dir}' created but is not writable.")
                        issues_found +=1
                except Exception as e_mkdir:
                    errors.append(f"{name}: Directory '{log_dir}' does not exist and could not be created: {e_mkdir}")
                    issues_found +=1
            elif not os.access(log_dir, os.W_OK):
                errors.append(f"{name}: Directory '{log_dir}' for '{log_abs_path}' is not writable.")
                issues_found +=1
            else:
                 val_logger.debug(f"{name} directory ('{log_dir}') is writable for new file '{log_abs_path}'.")


    # 3. REPORTS_DIR, HANDSHAKE_CAPTURE_DIR, etc. (directories that modules might write to)
    dirs_to_check_writable = {
        "REPORTS_DIR": getattr(app_config, 'REPORTS_DIR', os.path.join(config.APP_BASE_DIR, 'reports')),
        "HANDSHAKE_CAPTURE_DIR": getattr(app_config, 'HANDSHAKE_CAPTURE_DIR', os.path.join(config.APP_BASE_DIR, 'captures')),
        # Add other output directories from config.py here
    }
    for name, path in dirs_to_check_writable.items():
        dir_abs_path = os.path.abspath(path)
        if os.path.exists(dir_abs_path):
            if not (os.access(dir_abs_path, os.W_OK) and os.access(dir_abs_path, os.X_OK)):
                errors.append(f"{name}: Path '{dir_abs_path}' exists but is not writable/executable (needed for listing/creating files).")
                issues_found +=1
            else:
                val_logger.debug(f"{name} ('{dir_abs_path}') exists and is accessible/writable.")
        else: # Directory doesn't exist, check if parent is writable to allow creation by modules
            parent_dir = os.path.dirname(dir_abs_path)
            if not os.path.exists(parent_dir): # Should not happen if APP_BASE_DIR is root of project
                 errors.append(f"{name}: Parent directory '{parent_dir}' for '{dir_abs_path}' does not exist.")
                 issues_found +=1
            elif not (os.access(parent_dir, os.W_OK) and os.access(parent_dir, os.X_OK)):
                errors.append(f"{name}: Parent directory '{parent_dir}' for '{dir_abs_path}' is not writable/executable. Directory creation by modules might fail.")
                issues_found +=1
            else:
                val_logger.info(f"{name} ('{dir_abs_path}') does not exist but parent ('{parent_dir}') is writable/executable. Modules should be able to create it.")


    # 4. Script Paths
    scripts_to_check = {
        "START_MON_SH_PATH": getattr(app_config, 'START_MON_SH_PATH', os.path.join(config.APP_BASE_DIR, 'start-mon.sh')),
        "SCAN_SH_PATH": getattr(app_config, 'SCAN_SH_PATH', os.path.join(config.APP_BASE_DIR, 'scan.sh')), # If it were still used
    }
    for name, path in scripts_to_check.items():
        if path:
            script_abs_path = os.path.abspath(path) # Path is already absolute from config.py
            if "scan.sh" in name and path.endswith('scan.sh'): # Special handling for scan.sh if it's optional/legacy
                 if not os.path.exists(script_abs_path):
                     val_logger.debug(f"{name}: Optional script path '{script_abs_path}' (from '{path}') does not exist. This may be fine if not used.")
                 elif not os.access(script_abs_path, os.X_OK): # If it exists, it should be executable
                     warnings.append(f"{name}: Optional script '{script_abs_path}' (from '{path}') exists but is not executable.")
                     issues_found +=1
                 else:
                     val_logger.debug(f"{name} ('{script_abs_path}') found and executable.")
                 continue # Move to next script

            if not os.path.exists(script_abs_path):
                warnings.append(f"{name}: Script path '{script_abs_path}' (from '{path}') does not exist.")
                issues_found +=1
            elif not os.access(script_abs_path, os.X_OK):
                warnings.append(f"{name}: Script '{script_abs_path}' (from '{path}') is not executable.")
                issues_found +=1
            else:
                val_logger.debug(f"{name} ('{script_abs_path}') found and executable.")
        else: # Path not configured (e.g. if it was empty string from env var)
             val_logger.debug(f"{name} is not configured or path is empty.")


    # 5. LOG_LEVEL
    log_level_str = getattr(app_config, 'LOG_LEVEL', 'INFO').upper()
    numeric_config_level = getattr(logging, log_level_str, None)
    if not isinstance(numeric_config_level, int):
        warnings.append(f"LOG_LEVEL: Value '{app_config.LOG_LEVEL}' is invalid. Root logger defaulted to INFO.")
        # This issue is already handled by the root logger setup, this is just an explicit startup warning.
        issues_found +=1
    else:
        val_logger.debug(f"LOG_LEVEL ('{log_level_str}') is valid.")

    # Summary
    if errors:
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
