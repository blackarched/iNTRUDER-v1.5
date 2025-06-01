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
import http.server
import json # For parsing JSON request bodies and creating JSON responses
import threading # For running the server in a separate thread to allow graceful shutdown
import os # Already imported, but ensure it's available for shutdown
import signal # Already imported
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


# --- Service Functions (migrated from Flask routes) ---
# These functions will be called by the IntruderApiHandler.
# They contain the core logic previously in the Flask route handlers.

def start_monitor_mode(data):
    iface_to_mon = data.get('iface', config.DEFAULT_IFACE)
    if not interface_exists(iface_to_mon):
        msg = f"Base interface {iface_to_mon} not found. Cannot start monitor mode."
        logger.error(msg)
        log_event("monitor_mode_failed", {"interface": iface_to_mon, "reason": "Base interface not found"})
        return {'status': 'error', 'message': msg}, 400

    if config.MAC_CHANGE_ENABLED:
        logger.info(f"MAC_CHANGE_ENABLED is True. Attempting to change MAC for {iface_to_mon} before starting monitor mode.")
        mac_changer = MACChanger()
        if mac_changer._check_macchanger_installed():
            original_mac = mac_changer.get_current_mac(iface_to_mon)
            if original_mac:
                logger.info(f"Original MAC for {iface_to_mon}: {original_mac}")
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

    script_path = config.START_MON_SH_PATH # This is just the script name or relative path from project root
    try:
        # Ensure SUDO_COMMAND is used here. START_MON_SH_PATH should not contain sudo itself.
        cmd = [config.SUDO_COMMAND, script_path, iface_to_mon]
        logger.info(f"Attempting to start monitor mode on {iface_to_mon} using command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        logger.debug(f"Monitor mode script stdout: {result.stdout}")
        if result.stderr:
            logger.warning(f"Monitor mode script stderr: {result.stderr}")

        monitor_interface_name = iface_to_mon + config.MONITOR_IFACE_SUFFIX
        final_event_data = {
            "base_interface": iface_to_mon, "monitor_interface_expected": monitor_interface_name,
            "command": ' '.join(cmd), "script_rc": result.returncode,
            "script_output": result.stdout, "script_error": result.stderr
        }

        if result.returncode == 0:
            if interface_exists(monitor_interface_name) and is_monitor_mode(monitor_interface_name):
                logger.info(f"Successfully enabled monitor mode on {monitor_interface_name} (derived from {iface_to_mon}).")
                final_event_data.update({"success": True, "verified_monitor_interface": monitor_interface_name, "status_message": "Monitor mode enabled and verified."})
                log_event("monitor_mode_enabled", final_event_data)
                return {'status': 'success', 'message': f'Monitor mode enabled on {monitor_interface_name}.', 'output': result.stdout, 'error_output': result.stderr, "monitor_interface": monitor_interface_name}, 200
            else:
                logger.error(f"start-mon.sh script ran for {iface_to_mon} (RC:0), but expected monitor interface {monitor_interface_name} is not in monitor mode or does not exist.")
                final_event_data.update({"success": False, "status_message": "Script executed but monitor mode verification failed."})
                log_event("monitor_mode_failed_verification", final_event_data)
                return {'status': 'error', 'message': f"Failed to verify monitor mode on {monitor_interface_name} after script execution.", 'output': result.stdout, 'error_output': result.stderr}, 500
        else:
            final_event_data.update({"success": False, "status_message": "start-mon.sh script failed."})
            log_event("monitor_mode_script_failed", final_event_data)
            return {'status': 'error', 'message': f"start-mon.sh script failed for {iface_to_mon}.", 'output': result.stdout, 'error_output': result.stderr, 'return_code': result.returncode}, 500
    except subprocess.CalledProcessError as e:
        logger.error(f"Error starting monitor mode. Command: '{' '.join(e.cmd)}' failed with code {e.returncode}", exc_info=True)
        log_event("monitor_mode_script_failed_exception", {"interface": iface_to_mon, "command": ' '.join(e.cmd), "success": False, "output": e.stdout, "error": e.stderr, "return_code": e.returncode})
        return {'status': 'error', 'message': e.stderr or "start-mon.sh execution failed.", 'output': e.stdout, 'command': e.cmd, 'return_code': e.returncode}, 500
    except subprocess.TimeoutExpired as e:
        logger.error(f"Timeout starting monitor mode on {iface_to_mon}. Command: '{' '.join(e.cmd)}'", exc_info=True)
        log_event("monitor_mode_script_timeout", {"interface": iface_to_mon, "command": ' '.join(e.cmd), "success": False, "error": "TimeoutExpired"})
        return {'status': 'error', 'message': f'Timeout starting monitor mode on {iface_to_mon}', 'command': e.cmd}, 500
    except FileNotFoundError:
        actual_cmd_not_found = cmd[0] # Default to SUDO_COMMAND
        if cmd[0] == config.SUDO_COMMAND and not os.path.exists(cmd[1]): # Check script path if sudo was the command
            actual_cmd_not_found = cmd[1]
        elif cmd[0] != config.SUDO_COMMAND and not os.path.exists(cmd[0]): # Check command itself if not sudo (less likely here)
            actual_cmd_not_found = cmd[0]

        logger.error(f"Command '{actual_cmd_not_found}' for starting monitor mode not found. Ensure SUDO_COMMAND is valid and START_MON_SH_PATH ('{script_path}') is correct.", exc_info=True)
        log_event("monitor_mode_script_not_found", {"interface": iface_to_mon, "script_path": script_path, "sudo_command": config.SUDO_COMMAND, "success": False, "error": "FileNotFoundError"})
        return {'status': 'error', 'message': f"Command '{actual_cmd_not_found}' not found. Check server logs for details."}, 404
    except Exception as e:
        logger.exception(f"An unexpected error occurred while starting monitor mode on {iface_to_mon}")
        log_event("monitor_mode_unexpected_error", {"interface": iface_to_mon, "success": False, "error": str(e)})
        return {'status': 'error', 'message': str(e)}, 500

def start_scan(data):
    iface_to_use = data.get('interface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    duration = data.get('duration', "30")
    try:
        duration_seconds = int(duration)
    except ValueError:
        logger.warning(f"Invalid duration provided: '{duration}'. Defaulting to 30 seconds.")
        duration_seconds = 30

    if not iface_to_use:
        logger.error("No interface provided for scan.")
        return {'status': 'error', 'message': 'Interface not provided for scan.'}, 400

    logger.info(f"Scan request received for interface {iface_to_use} for {duration_seconds} seconds.")
    try:
        if not os.path.exists(f"/sys/class/net/{iface_to_use}"):
            logger.error(f"Scan requested on non-existent interface: {iface_to_use}. Please ensure it's in monitor mode.")
            return {'status': 'error', 'message': f"Interface {iface_to_use} does not exist. Is it in monitor mode?"}, 400

        scanner = AdaptiveScanner(interface=iface_to_use)
        scan_results = scanner.scan(duration_seconds=duration_seconds)

        if 'error' in scan_results:
            logger.error(f"AdaptiveScanner failed for interface {iface_to_use}: {scan_results['error']}")
            log_event("scan_failed", {"interface": iface_to_use, "duration": duration_seconds, "error": scan_results['error'], "details": scan_results})
            return {"status": "error", "message": "Scan operation failed.", "details": scan_results['error']}, 500

        num_networks = len(scan_results.get('networks',[]))
        num_clients = len(scan_results.get('clients',[]))
        logger.info(f"Scan completed on {iface_to_use}. Found {num_networks} networks, {num_clients} clients.")
        log_event("scan_completed", {"interface": iface_to_use, "duration": duration_seconds, "network_count": num_networks, "client_count": num_clients})
        return scan_results, 200
    except Exception as e:
        logger.error(f"An unexpected server error occurred in /api/scan/start for interface {iface_to_use}: {e}", exc_info=True)
        log_event("scan_api_error", {"interface": iface_to_use, "duration": duration_seconds, "error": str(e)})
        return {'status': 'error', 'message': f"An unexpected server error occurred: {str(e)}"}, 500

def start_deauth_attack(data):
    iface = data.get('iface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    target_bssid = data.get('target_bssid', data.get('target'))
    client_mac = data.get('client_mac', 'FF:FF:FF:FF:FF:FF')
    count = data.get('count', 10)

    if not target_bssid:
        return {'status': 'error', 'message': 'Target BSSID (target_bssid) not provided'}, 400

    log_event("deauth_attack_started", {"interface": iface, "target_bssid": target_bssid, "client_mac": client_mac, "count": count})
    deauth = DeauthAttack(iface=iface, target_mac=target_bssid, count=count)
    _services['deauth'] = deauth # Assuming _services is accessible or passed appropriately
    deauth_result = deauth.run()
    success = deauth_result.get('status') == 'success' if isinstance(deauth_result, dict) else False
    log_event("deauth_attack_completed", {"interface": iface, "target_bssid": target_bssid, "client_mac": client_mac, "count": count, "success": success, "details": deauth_result})
    return deauth_result, 200 if success else 500

def start_handshake_capture(data):
    iface = data.get('iface', f"{config.DEFAULT_IFACE}{config.MONITOR_IFACE_SUFFIX}")
    ssid = data.get('ssid')
    bssid = data.get('bssid')
    channel = data.get('channel')

    if not ssid and not bssid:
        return {'status': 'error', 'message': 'Either SSID (ssid) or Target BSSID (bssid) must be provided for handshake capture'}, 400

    log_event("handshake_capture_started", {"interface": iface, "ssid": ssid, "bssid": bssid, "channel": channel})
    hs_capture_instance = HandshakeCapture(iface=iface, ssid=ssid, bssid=bssid, channel=channel)
    _services['handshake'] = hs_capture_instance
    capture_details = hs_capture_instance.capture()
    is_successful_capture = capture_details.get("status") == "success" or capture_details.get("status") == "success_with_errors"
    log_event("handshake_capture_completed", {"interface": iface, "ssid": ssid, "bssid": bssid, "channel": channel, "success": is_successful_capture, "file": capture_details.get('file'), "details": capture_details})
    return capture_details, 200 if is_successful_capture else 500

def start_crack_wifi(data):
    handshake_file = data.get('handshake_file')
    wordlist_from_request = data.get('wordlist')
    bssid = data.get('bssid') # Extract optional BSSID
    wordlist_to_use = None

    if wordlist_from_request:
        wordlist_to_use = wordlist_from_request
        logger.info(f"Using wordlist from request: {wordlist_to_use}")
    elif getattr(config, 'DEFAULT_WORDLIST', None):
        wordlist_to_use = config.DEFAULT_WORDLIST
        logger.info(f"Using DEFAULT_WORDLIST from config: {wordlist_to_use}")
        if not os.path.exists(wordlist_to_use) or not os.access(wordlist_to_use, os.R_OK):
            msg = f"DEFAULT_WORDLIST '{wordlist_to_use}' is configured but not found or not readable."
            logger.error(msg)
            log_event("crack_attempt_failed", {"handshake_file": handshake_file, "bssid": bssid, "reason": "Default wordlist invalid", "default_wordlist_path": wordlist_to_use})
            return {"status": "error", "message": msg}, 500
    else:
        msg = "Wordlist not provided in request and no DEFAULT_WORDLIST is configured."
        logger.warning(msg)
        log_event("crack_attempt_failed", {"handshake_file": handshake_file, "bssid": bssid, "reason": "No wordlist provided or configured"})
        return {"status": "error", "message": msg}, 400

    if not handshake_file:
        return {'status': 'error', 'message': 'Handshake file (handshake_file) not provided'}, 400

    log_event_details_started = {"handshake_file": handshake_file, "wordlist_used": wordlist_to_use}
    if bssid:
        log_event_details_started["bssid"] = bssid
    log_event("crack_attempt_started", log_event_details_started)

    cracker = WifiCracker(handshake_file=handshake_file, wordlist=wordlist_to_use, bssid=bssid) # Pass bssid
    _services['cracker'] = cracker
    crack_result = cracker.run()

    password_found = crack_result.get('status') == 'success' and crack_result.get('password') is not None if isinstance(crack_result, dict) else False

    log_event_details_completed = {
        "handshake_file": handshake_file,
        "wordlist_used": wordlist_to_use,
        "success": password_found,
        "password_found": crack_result.get('password') if password_found else None,
        "details": crack_result
    }
    if bssid:
        log_event_details_completed["bssid"] = bssid
    log_event("crack_attempt_completed", log_event_details_completed)

    return crack_result, 200 if crack_result.get('status') in ['success', 'failed'] else 500

def start_rogue_ap(data):
    iface = data.get('iface')
    ssid = data.get('ssid')
    channel = data.get('channel', 6)
    ap = RogueAP(iface=iface, ssid=ssid, channel=channel)
    log_event("rogue_ap_start_requested", {"interface": iface, "ssid": ssid, "channel": channel})
    procs = ap.start_services()
    _services['rogue_ap'] = ap
    return {'status': 'running', 'procs': list(procs.keys())}, 200

def stop_rogue_ap(data): # data might not be used but kept for consistency
    ap = _services.pop('rogue_ap', None)
    if not ap:
        return {"status": "error", 'message': 'Rogue AP not running'}, 400
    log_event("rogue_ap_stop_requested", {"interface": getattr(ap, 'iface', 'unknown'), "ssid": getattr(ap, 'ssid', 'unknown')})
    ap.cleanup()
    return {'status': 'stopped'}, 200

def start_mitm_proxy(data):
    port = data.get('port', 8081)
    mode = data.get('mode', 'transparent')
    log_event("mitm_proxy_start_requested", {"port": port, "mode": mode})
    mitm = MitmProxy(listen_port=port, mode=mode)
    mitm.start()
    _services['mitm'] = mitm
    return {'status': 'running', 'port': port}, 200

def stop_mitm_proxy(data): # data might not be used
    mitm = _services.pop('mitm', None)
    if not mitm:
        return {"status": "error", 'message': 'MITM not running'}, 400
    log_event("mitm_proxy_stop_requested", {"port": getattr(mitm.master.options, 'listen_port', 'unknown') if mitm.master else 'unknown'})
    mitm.shutdown()
    return {'status': 'stopped'}, 200

def start_wps_attack(data):
    iface = data.get('iface')
    bssid = data.get('bssid')
    timeout = data.get('timeout', 3600)
    multi = data.get('multi', False)
    wps = WPSAttack(iface=iface, target_bssid=bssid)
    _services['wps'] = wps
    wps_result = wps.run(timeout=timeout, multi=multi)
    http_status_code = 200 if wps_result.get('status') in ['completed', 'error_user_input_related'] else 500
    return wps_result, http_status_code

def generate_reporting(data): # data might not be used
    logger.info("Report generation requested via API.")
    log_event("report_generation_requested", {"formats_requested": ["json", "markdown"], "triggered_by": "api"})
    report_generator = ReportGenerator()
    json_report_path = report_generator.generate_json_report()
    if json_report_path: logger.info(f"JSON report generated: {json_report_path}")
    else: logger.warning("JSON report generation failed or no events to report.")
    md_report_path = report_generator.generate_markdown_report()
    if md_report_path: logger.info(f"Markdown report generated: {md_report_path}")
    else: logger.warning("Markdown report generation failed or no events to report.")
    success = bool(json_report_path or md_report_path)
    response_data = {
        "status": "success" if success else "no_events_or_failure",
        "message": "Report generation process completed." if success else "No events to report or report generation failed for all formats.",
        "json_report_path": json_report_path,
        "markdown_report_path": md_report_path
    }
    log_event("report_generation_completed", {"success": success, "json_report_generated": bool(json_report_path), "markdown_report_generated": bool(md_report_path), "json_report_path": json_report_path, "markdown_report_path": md_report_path})
    return response_data, 200

# --- End Service Functions ---


# --- HTTP Server Implementation ---
_services = {} # Global process/state holders, to be managed by the handler or server instance

class IntruderApiHandler(http.server.BaseHTTPRequestHandler):
    def _send_json_response(self, data, status_code=200): # Ensure status_code is passed through
        self.send_response(int(status_code)) # Ensure status_code is int
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS') # Allow OPTIONS
        self.send_header('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type') # Common headers
        self.end_headers()
        response_body = json.dumps(data).encode('utf-8') # data should be the first arg
        self.wfile.write(response_body)

    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS preflight."""
        self.send_response(204) # No Content
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/health':
            self._send_json_response({'status': 'healthy'}, 200)
        else:
            self._send_json_response({'error': 'Not Found'}, 404)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data_bytes = self.rfile.read(content_length)
        try:
            data = json.loads(post_data_bytes.decode('utf-8')) if post_data_bytes else {}
        except json.JSONDecodeError:
            self._send_json_response({'error': 'Invalid JSON payload'}, 400)
            return

        routes = {
            '/api/monitor/start': start_monitor_mode,
            '/api/scan/start': start_scan,
            '/api/deauth/start': start_deauth_attack,
            '/api/handshake/start': start_handshake_capture,
            '/api/crack/start': start_crack_wifi,
            '/api/rogue_ap/start': start_rogue_ap,
            '/api/rogue_ap/stop': stop_rogue_ap,
            '/api/mitm/start': start_mitm_proxy,
            '/api/mitm/stop': stop_mitm_proxy,
            '/api/wps/start': start_wps_attack,
            '/api/reporting/generate': generate_reporting,
        }

        if self.path in routes:
            handler_func = routes[self.path]
            try:
                response_data, status_code = handler_func(data)
                self._send_json_response(response_data, status_code)
            except Exception as e:
                logger.exception(f"Error handling POST request for {self.path}")
                self._send_json_response({'error': 'Internal Server Error', 'details': str(e)}, 500)
        else:
            self._send_json_response({'error': 'Not Found'}, 404)

# --- End HTTP Server Implementation ---


# Imports for service classes (ensure these are still correct and used by service functions)
from .plugins.rogue_ap import RogueAP
from .plugins.mitm import MitmProxy
from .plugins.wps_attack import WPSAttack
from .plugins.opsec_utils import MACChanger
from .plugins.scanner import AdaptiveScanner
from .deauth_attack import DeauthAttack
from .handshake_capture_module import HandshakeCapture
from .wifi_cracker_module import WifiCracker
from .core.event_logger import log_event # Used by service functions
from .core.network_utils import interface_exists, is_monitor_mode # Used by service functions
from .reporting import ReportGenerator # Used by service functions

# Global http_server instance for shutdown
http_server = None

# Graceful shutdown (remains largely the same, ensure _services is accessible)
def shutdown_handler(signum, frame):
    global http_server # Ensure http_server is accessible
    logger.info("Received signal %s. Shutting down iNTRUDER server and all services...", signal.Signals(signum).name)

    # Stop services first
    for name, svc in list(_services.items()): # Iterate over a copy
        logger.info(f"Attempting to stop service: {name}...")
        try:
            if hasattr(svc, 'shutdown'):
                svc.shutdown()
            elif hasattr(svc, 'cleanup'):
                svc.cleanup()
            logger.info(f"Successfully stopped {name}")
        except Exception:
            logger.exception(f"Error stopping {name}")
        finally:
            _services.pop(name, None)

    logger.info("All services processed.")

    if http_server: # Check if http_server is initialized
        logger.info("Shutting down HTTP server...")
        threading.Thread(target=http_server.shutdown, daemon=True).start()
        logger.info("HTTP server shutdown initiated.")

    logger.info("Exiting application.")
    os._exit(0) # Force exit

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)


# --- Configuration Validation Function ---
def validate_config(app_config):
    """
    Validates critical configuration settings at startup.
    Logs warnings or errors if issues are found.
    """
    val_logger = logging.getLogger(__name__ + ".config_validator")
    issues_found = 0
    warnings = []
    errors = []

    # 1. DEFAULT_WORDLIST
    default_wordlist = getattr(app_config, 'DEFAULT_WORDLIST', None)
    if default_wordlist:
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
    else:
        if not os.path.exists(event_log_dir):
            try:
                os.makedirs(event_log_dir, exist_ok=True)
                val_logger.info(f"Created directory for EVENT_LOG_FILE: {event_log_dir}")
                if not os.access(event_log_dir, os.W_OK):
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
    if os.path.exists(reports_dir_abs_path):
        if not os.access(reports_dir_abs_path, os.W_OK) or not os.access(reports_dir_abs_path, os.X_OK):
            errors.append(f"REPORTS_DIR: Path '{reports_dir_abs_path}' exists but is not writable/browsable.")
            issues_found +=1
        else:
            val_logger.debug(f"REPORTS_DIR ('{reports_dir_abs_path}') exists and is accessible.")
    else:
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
    }
    for name, path in scripts_to_check.items():
        if path:
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
        issues_found +=1
    else:
        val_logger.debug(f"LOG_LEVEL ('{log_level_str}') is valid.")

    # Summary
    if errors:
        for error_msg in errors: # Corrected: iterate over the 'errors' list directly
            val_logger.error(f"Configuration Error: {error_msg}")
    if warnings:
        for warning_msg in warnings:
            val_logger.warning(f"Configuration Warning: {warning_msg}")

    if issues_found == 0:
        val_logger.info("Configuration validation successful. All critical settings appear valid.")
    else:
        val_logger.warning(f"Configuration validation complete. Issues found: {issues_found} (see warnings/errors above).")

    return not errors


if __name__ == '__main__':
    # Perform configuration validation at startup
    if not validate_config(config):
        logger.critical("Critical configuration errors found. Exiting.")
        sys.exit(1)

    global http_server # Ensure http_server is accessible in this scope for shutdown_handler
    host = '0.0.0.0'
    # Use a default for PORT from config if INTRUDER_PORT env var is not set
    port_from_config = getattr(config, 'PORT', 5000) # Assuming config might have a PORT attribute
    port = int(os.environ.get('INTRUDER_PORT', port_from_config))


    http_server = http.server.HTTPServer((host, port), IntruderApiHandler)
    logger.info(f"Starting iNTRUDER server on {host}:{port}")
    logger.info(f"Effective log level: {logging.getLevelName(root_logger.getEffectiveLevel())}")

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received (serve_forever). Shutting down via handler...")
        # shutdown_handler will be called by the signal, no need to call explicitly.
        # If it wasn't, we might call: shutdown_handler(signal.SIGINT, None)
    finally:
        # This block executes after serve_forever() returns, which happens after shutdown() is called.
        logger.info("HTTP server has been shut down (from finally block).")
