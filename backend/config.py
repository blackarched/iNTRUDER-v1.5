# backend/config.py
"""
Configuration settings for the iNTRUDER application.

This module centralizes all configuration variables for the application.
Settings can be sourced from environment variables, with sensible defaults provided.
Review these settings carefully before deploying in a production environment,
especially paths to tools, wordlists, and directories.

Environment Variables:
    - INTRUDER_DEFAULT_IFACE: Default wireless interface.
    - INTRUDER_MONITOR_IFACE_SUFFIX: Suffix for monitor mode interface names.
    - INTRUDER_LOG_LEVEL: Application-wide logging level (e.g., DEBUG, INFO, WARNING).
    - INTRUDER_LOG_FILE: Path to the main application log file.
    - INTRUDER_EVENT_LOG_FILE: Path to the session events log file (JSONL format).
    - INTRUDER_MAC_CHANGE_ENABLED: Set to "true" or "1" to enable MAC address changes.
    - INTRUDER_REPORTS_DIR: Directory for saving reports.
    - INTRUDER_AIRCRACK_TIMEOUT: Timeout in seconds for aircrack-ng processes.
    - INTRUDER_SCAN_SH_PATH: Path to a custom network scanning script.
    - INTRUDER_START_MON_SH_PATH: Path to a script for starting monitor mode.
    - INTRUDER_DEFAULT_WORDLIST: Default wordlist path for cracking.
    - INTRUDER_HANDSHAKE_CAPTURE_DIR: Directory for storing captured handshakes.
    - INTRUDER_HANDSHAKE_CAPTURE_PREFIX: Filename prefix for handshake captures.
    - DATABASE_URL: (Example) Database connection string.
    - API_HOST: (Example) Host for the API server.
    - API_PORT: (Example) Port for the API server.
    - DEBUG_MODE: (Example) Set to "true" or "1" to enable debug mode.
"""
import os
import logging

config_logger: logging.Logger = logging.getLogger(__name__)

# --- Application Base Directory ---
# Assumes config.py is in the 'backend' directory, and base is the project root '/app'.
APP_BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# If config.py was directly in /app, APP_BASE_DIR would be:
# APP_BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))


# --- General Settings ---
DEFAULT_IFACE: str = os.getenv('INTRUDER_DEFAULT_IFACE', "wlan0")
MONITOR_IFACE_SUFFIX: str = os.getenv('INTRUDER_MONITOR_IFACE_SUFFIX', "mon")


# --- Logging Configuration ---
# Log level for the application's internal logger. Options: DEBUG, INFO, WARNING, ERROR, CRITICAL.
LOG_LEVEL: str = os.getenv('INTRUDER_LOG_LEVEL', "INFO").upper()
# Path to the main application log file.
LOG_FILE: str = os.getenv('INTRUDER_LOG_FILE', os.path.join(APP_BASE_DIR, 'logs', 'intruder.log'))
# Path to the event log file (JSON Lines format).
EVENT_LOG_FILE: str = os.getenv('INTRUDER_EVENT_LOG_FILE', os.path.join(APP_BASE_DIR, 'logs', 'session_events.jsonl'))


# --- Operational Security (OpSec) Settings ---
# Enable or disable automatic MAC address changing during certain operations (e.g., deauth).
# Set to "true" or "1" via environment variable to enable.
_mac_change_enabled_env: str = os.getenv('INTRUDER_MAC_CHANGE_ENABLED', 'False').lower()
MAC_CHANGE_ENABLED: bool = _mac_change_enabled_env in ['true', '1', 'yes']


# --- Reporting ---
# Directory where reports (e.g., scan results) are saved.
REPORTS_DIR: str = os.getenv('INTRUDER_REPORTS_DIR', os.path.join(APP_BASE_DIR, 'reports'))


# --- Tool-Specific Timeouts ---
# Timeout in seconds for the aircrack-ng process.
# Provide as an integer.
_aircrack_timeout_env: str = os.getenv('INTRUDER_AIRCRACK_TIMEOUT', '3600')
AIRCRACK_TIMEOUT: int
try:
    AIRCRACK_TIMEOUT = int(_aircrack_timeout_env)
    if AIRCRACK_TIMEOUT <= 0:
        config_logger.warning(f"INTRUDER_AIRCRACK_TIMEOUT must be positive. Using default 3600s.")
        AIRCRACK_TIMEOUT = 3600
except ValueError:
    AIRCRACK_TIMEOUT = 3600 # Default to 1 hour if env var is invalid
    config_logger.warning(f"Invalid INTRUDER_AIRCRACK_TIMEOUT value '{_aircrack_timeout_env}'. Using default {AIRCRACK_TIMEOUT}s.")


# --- Paths to External Shell Scripts (Optional) ---
# These scripts might be used for extended functionalities if present.
# Path to a custom network scanning script.
SCAN_SH_PATH: str = os.getenv('INTRUDER_SCAN_SH_PATH', os.path.join(APP_BASE_DIR, 'scripts', 'scan.sh'))
# Path to a script for starting a monitor mode interface.
START_MON_SH_PATH: str = os.getenv('INTRUDER_START_MON_SH_PATH', os.path.join(APP_BASE_DIR, 'scripts', 'start-mon.sh'))


# --- Cracking Utilities ---
# Default wordlist path for Wi-Fi password cracking attempts.
# IMPORTANT: This default path is intentionally non-existent for testing purposes.
# In a production or real testing deployment, this MUST be changed to a valid path
# to an actual wordlist file, or set via the INTRUDER_DEFAULT_WORDLIST environment variable.
# Modules using this path should handle FileNotFoundError gracefully.
DEFAULT_WORDLIST: str = os.getenv('INTRUDER_DEFAULT_WORDLIST', os.path.join(APP_BASE_DIR, 'wordlists', 'default_nonexistent_wordlist.txt'))
# Example of a common wordlist path (ensure it exists on your system if used):
# DEFAULT_WORDLIST: str = os.getenv('INTRUDER_DEFAULT_WORDLIST', "/usr/share/wordlists/rockyou.txt")


# --- Handshake Capture Settings ---
# Directory where captured handshake files (.cap) are stored.
HANDSHAKE_CAPTURE_DIR: str = os.getenv('INTRUDER_HANDSHAKE_CAPTURE_DIR', os.path.join(APP_BASE_DIR, 'captures'))
# Default prefix for handshake capture filenames.
HANDSHAKE_CAPTURE_PREFIX: str = os.getenv('INTRUDER_HANDSHAKE_CAPTURE_PREFIX', "handshake")


# --- Database Settings (Example - Not fully implemented in all modules yet) ---
# Example: SQLALCHEMY_DATABASE_URI: str = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(APP_BASE_DIR, 'app.db'))


# --- API Settings (Example) ---
# Example: API_HOST: str = os.getenv('API_HOST', '0.0.0.0')
# Example: API_PORT: int = int(os.getenv('API_PORT', '8000'))


# --- Development/Debug Settings ---
# Example: DEBUG_MODE: bool = os.getenv('DEBUG_MODE', 'False').lower() in ['true', '1', 'yes']


def initialize_directories() -> None:
    """
    Creates essential application directories if they don't exist.
    This function should ideally be called once at application startup.
    """
    config_logger.info("Initializing application directories...")
    dirs_to_create = {
        "Log Directory": os.path.dirname(LOG_FILE),
        "Event Log Directory": os.path.dirname(EVENT_LOG_FILE),
        "Reports Directory": REPORTS_DIR,
        "Handshake Capture Directory": HANDSHAKE_CAPTURE_DIR,
        # "Default Wordlist Directory": os.path.dirname(DEFAULT_WORDLIST) # Only if wordlists are managed within app dir
    }

    for name, path_str in dirs_to_create.items():
        if not path_str: # Handle cases where a config path might be empty (e.g. LOG_FILE = "")
            config_logger.debug(f"Skipping directory creation for {name} as path is not set or empty.")
            continue
        try:
            os.makedirs(path_str, exist_ok=True)
            config_logger.debug(f"Ensured directory exists for {name}: {path_str}")
        except OSError as e:
            config_logger.error(f"Failed to create directory for {name} at {path_str}: {e}", exc_info=True)
        except Exception as e_gen: # Catch any other unexpected errors during makedirs
            config_logger.error(f"Unexpected error creating directory for {name} at {path_str}: {e_gen}", exc_info=True)

    # Specific warning for DEFAULT_WORDLIST if it's the placeholder and doesn't exist
    # Check if DEFAULT_WORDLIST is the default placeholder and if it doesn't exist
    # Using 'default_nonexistent_wordlist.txt' as the specific placeholder filename from the instructions
    if DEFAULT_WORDLIST.endswith('default_nonexistent_wordlist.txt') and not os.path.exists(DEFAULT_WORDLIST):
        config_logger.warning(
            f"DEFAULT_WORDLIST is set to the placeholder '{DEFAULT_WORDLIST}' which does not exist. "
            "Cracking features requiring a wordlist will not function correctly until a valid wordlist path is configured."
        )


# To verify paths during development:
if __name__ == '__main__':
    # Basic logging config for direct script execution to see config_logger messages
    logging.basicConfig(
        level=logging.DEBUG, # Show DEBUG level for this direct execution
        format="[%(levelname)s] %(name)s: %(message)s"
    )

    config_logger.info("Running config.py directly for verification:")
    config_logger.info(f"Application Base Directory (APP_BASE_DIR): {APP_BASE_DIR}")
    config_logger.info(f"Log Level: {LOG_LEVEL}")
    config_logger.info(f"Log File Path: {LOG_FILE}")
    config_logger.info(f"Event Log File Path: {EVENT_LOG_FILE}")
    config_logger.info(f"Reports Directory: {REPORTS_DIR}")
    config_logger.info(f"Default Wordlist Path: {DEFAULT_WORDLIST}")
    config_logger.info(f"Handshake Capture Directory: {HANDSHAKE_CAPTURE_DIR}")
    config_logger.info(f"Scan Script Path: {SCAN_SH_PATH}")
    config_logger.info(f"Start Monitor Script Path: {START_MON_SH_PATH}")
    config_logger.info(f"MAC Change Enabled: {MAC_CHANGE_ENABLED}")
    config_logger.info(f"Aircrack Timeout: {AIRCRACK_TIMEOUT}")

    # Call the new function to create directories and show wordlist warning if applicable
    # This should ideally be called by the main application on startup (e.g. server.py)
    initialize_directories()
    config_logger.info("Directory initialization attempt complete (check logs for details).")
