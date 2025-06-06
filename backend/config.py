# backend/config.py
import os

# --- Application Base Directory ---
# Assumes config.py is in the 'backend' directory, and base is the project root '/app'.
# If config.py is at /app/backend/config.py, then its dirname is /app/backend.
# The parent of /app/backend is /app.
APP_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# If config.py was directly in /app, APP_BASE_DIR would be:
# APP_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# --- General Settings ---
DEFAULT_IFACE = os.getenv('INTRUDER_DEFAULT_IFACE', "wlan0") # Env: INTRUDER_DEFAULT_IFACE
# Suffix to append to the interface name when creating a monitor interface (if applicable by scripts).
MONITOR_IFACE_SUFFIX = os.getenv('INTRUDER_MONITOR_IFACE_SUFFIX', "mon") # Env: INTRUDER_MONITOR_IFACE_SUFFIX


# --- Logging Configuration ---
# Log level for the application's internal logger. Options: DEBUG, INFO, WARNING, ERROR, CRITICAL.
LOG_LEVEL = os.getenv('INTRUDER_LOG_LEVEL', "DEBUG") # Env: INTRUDER_LOG_LEVEL
# Path to the main application log file.
LOG_FILE = os.getenv('INTRUDER_LOG_FILE', os.path.join(APP_BASE_DIR, 'logs', 'intruder.log')) # Env: INTRUDER_LOG_FILE
# Path to the event log file (JSON Lines format).
EVENT_LOG_FILE = os.getenv('INTRUDER_EVENT_LOG_FILE', os.path.join(APP_BASE_DIR, 'logs', 'session_events.jsonl')) # Env: INTRUDER_EVENT_LOG_FILE


# --- Operational Security (OpSec) Settings ---
# Enable or disable automatic MAC address changing during certain operations (e.g., deauth).
# Set to "true" or "1" via environment variable to enable.
_mac_change_enabled_env = os.getenv('INTRUDER_MAC_CHANGE_ENABLED', 'False').lower()
MAC_CHANGE_ENABLED = _mac_change_enabled_env in ['true', '1', 'yes'] # Env: INTRUDER_MAC_CHANGE_ENABLED


# --- Reporting ---
# Directory where reports (e.g., scan results) are saved.
REPORTS_DIR = os.getenv('INTRUDER_REPORTS_DIR', os.path.join(APP_BASE_DIR, 'reports')) # Env: INTRUDER_REPORTS_DIR


# --- Tool-Specific Timeouts ---
# Timeout in seconds for the aircrack-ng process.
# Provide as an integer.
_aircrack_timeout_env = os.getenv('INTRUDER_AIRCRACK_TIMEOUT', '3600') # Env: INTRUDER_AIRCRACK_TIMEOUT
try:
    AIRCRACK_TIMEOUT = int(_aircrack_timeout_env)
except ValueError:
    AIRCRACK_TIMEOUT = 3600 # Default to 1 hour if env var is invalid
    print(f"Warning: Invalid INTRUDER_AIRCRACK_TIMEOUT value '{_aircrack_timeout_env}'. Using default {AIRCRACK_TIMEOUT}s.")


# --- Paths to External Shell Scripts (Optional) ---
# These scripts might be used for extended functionalities if present.
# Path to a custom network scanning script.
SCAN_SH_PATH = os.getenv('INTRUDER_SCAN_SH_PATH', os.path.join(APP_BASE_DIR, 'scripts', 'scan.sh')) # Env: INTRUDER_SCAN_SH_PATH
# Path to a script for starting a monitor mode interface.
START_MON_SH_PATH = os.getenv('INTRUDER_START_MON_SH_PATH', os.path.join(APP_BASE_DIR, 'scripts', 'start-mon.sh')) # Env: INTRUDER_START_MON_SH_PATH


# --- Cracking Utilities ---
# Default wordlist path for Wi-Fi password cracking attempts.
# IMPORTANT: This default path is intentionally non-existent for testing purposes.
# In a production or real testing deployment, this MUST be changed to a valid path
# to an actual wordlist file, or set via the INTRUDER_DEFAULT_WORDLIST environment variable.
# Modules using this path should handle FileNotFoundError gracefully.
DEFAULT_WORDLIST = os.getenv('INTRUDER_DEFAULT_WORDLIST', os.path.join(APP_BASE_DIR, 'wordlists', 'default_wordlist.txt')) # Env: INTRUDER_DEFAULT_WORDLIST
# Example of a common wordlist path (ensure it exists on your system if used):
# DEFAULT_WORDLIST = os.getenv('INTRUDER_DEFAULT_WORDLIST', "/usr/share/wordlists/rockyou.txt")


# --- Handshake Capture Settings ---
# Directory where captured handshake files (.cap) are stored.
HANDSHAKE_CAPTURE_DIR = os.getenv('INTRUDER_HANDSHAKE_CAPTURE_DIR', os.path.join(APP_BASE_DIR, 'captures')) # Env: INTRUDER_HANDSHAKE_CAPTURE_DIR
# Default prefix for handshake capture filenames.
HANDSHAKE_CAPTURE_PREFIX = os.getenv('INTRUDER_HANDSHAKE_CAPTURE_PREFIX', "handshake") # Env: INTRUDER_HANDSHAKE_CAPTURE_PREFIX


# --- Database Settings (Example - Not fully implemented in all modules yet) ---
# Example: SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(APP_BASE_DIR, 'app.db')) # Env: DATABASE_URL


# --- API Settings (Example) ---
# Example: API_HOST = os.getenv('API_HOST', '0.0.0.0') # Env: API_HOST
# Example: API_PORT = int(os.getenv('API_PORT', '8000')) # Env: API_PORT


# --- Development/Debug Settings ---
# Example: DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() in ['true', '1', 'yes'] # Env: DEBUG_MODE

# Ensure log directories exist (optional, could be handled by logger setup)
# This is a good place to do it if paths are defined here.
# os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
# os.makedirs(os.path.dirname(EVENT_LOG_FILE), exist_ok=True)
# os.makedirs(REPORTS_DIR, exist_ok=True)
# os.makedirs(HANDSHAKE_CAPTURE_DIR, exist_ok=True)
# If using a wordlists directory within the project:
# os.makedirs(os.path.dirname(DEFAULT_WORDLIST), exist_ok=True) # Only if it's meant to be within APP_BASE_DIR

# To verify paths during development:
if __name__ == '__main__':
    print(f"Application Base Directory (APP_BASE_DIR): {APP_BASE_DIR}")
    print(f"Log File Path: {LOG_FILE}")
    print(f"Event Log File Path: {EVENT_LOG_FILE}")
    print(f"Reports Directory: {REPORTS_DIR}")
    print(f"Default Wordlist Path: {DEFAULT_WORDLIST}")
    print(f"Handshake Capture Directory: {HANDSHAKE_CAPTURE_DIR}")
    print(f"Scan Script Path: {SCAN_SH_PATH}")
    print(f"Start Monitor Script Path: {START_MON_SH_PATH}")
    print(f"MAC Change Enabled: {MAC_CHANGE_ENABLED}")
    print(f"Aircrack Timeout: {AIRCRACK_TIMEOUT}")
