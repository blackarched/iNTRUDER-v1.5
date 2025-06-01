# backend/config.py
DEFAULT_IFACE = "wlan0"
MONITOR_IFACE_SUFFIX = "mon"
LOG_LEVEL = "DEBUG" # Keep DEBUG for testing this
LOG_FILE = "intruder.log"
MAC_CHANGE_ENABLED = False # Keep False to simplify test focus unless MAC change logs are desired
EVENT_LOG_FILE = "session_events.jsonl"
REPORTS_DIR = "reports"
AIRCRACK_TIMEOUT = 3600

# Paths to shell scripts
SCAN_SH_PATH = "./scan.sh" # Not primary, but validated if set
START_MON_SH_PATH = "./start-mon.sh"

# Default wordlist - set to a non-existent path for testing validation
DEFAULT_WORDLIST = "/path/to/non_existent_wordlist.txt"

# Handshake capture settings
HANDSHAKE_CAPTURE_DIR = "captures"
HANDSHAKE_CAPTURE_PREFIX = "handshake"

# --- Privilege Separation Configuration ---
# Command to use for privilege escalation (e.g., "sudo" or "su -c" for Termux tsu)
SUDO_COMMAND = "sudo"
# Directory where wrapper scripts for privileged operations are located.
# Default is for standard Linux. Termux might need e.g., "../scripts/" relative to backend,
# or an absolute path like "/data/data/com.termux/files/home/intruder/scripts/"
WRAPPER_SCRIPT_DIR = "/opt/intruder/scripts/"
# Note: For Termux, if WRAPPER_SCRIPT_DIR is relative, ensure it's relative to where the server is run from.
# Example Termux value: WRAPPER_SCRIPT_DIR = "scripts/" # If scripts are in project_root/scripts
