#!/bin/bash

# Script to enable monitor mode on a wireless interface using airmon-ng.
# Handles parameterization, idempotence, error checking, and logging.

# Exit on error, treat unset variables as an error, and propagate exit status
set -euo pipefail

# --- Configuration & Variables ---
LOG_DIR="${INTRUDER_SCRIPT_LOG_DIR:-logs}" # Use INTRUDER_SCRIPT_LOG_DIR if set, otherwise default to "logs"
# Ensure LOG_DIR is created early if it's custom, before LOG_FILE is defined using it.
# The script already has `mkdir -p "${LOG_DIR}"` later, which is fine.

LOG_FILE_NAME_DEFAULT="monitor_mode_setup.log"
# Construct default log file path using the (potentially overridden) LOG_DIR
DEFAULT_LOG_FILE_PATH="${LOG_DIR}/${LOG_FILE_NAME_DEFAULT}"
# Use INTRUDER_MON_LOG_FILE if set, otherwise use the default constructed path
LOG_FILE="${INTRUDER_MON_LOG_FILE:-${DEFAULT_LOG_FILE_PATH}}"
DEFAULT_IFACE_CANDIDATES=("wlan0" "wlan1") # Common default wireless interface names

# --- Helper Functions ---

# Function to log messages to both stdout and a log file
log_message() {
    local type="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local log_prefix="[${timestamp}] [${type}]"

    echo -e "${log_prefix} ${message}" # Output to stdout/stderr
    echo "${log_prefix} ${message}" >> "${LOG_FILE}" # Append to log file
}

# Function to check if an interface exists
interface_exists_check() {
    local iface_name="$1"
    if ip link show "${iface_name}" > /dev/null 2>&1; then
        return 0 # Exists
    else
        return 1 # Does not exist
    fi
}

# Function to check if an interface is in monitor mode
is_monitor_mode_active() {
    local iface_name="$1"
    if interface_exists_check "${iface_name}"; then
        # Check 'Mode:Monitor' in iwconfig output. Grep returns 0 if found.
        if iwconfig "${iface_name}" 2>/dev/null | grep -q "Mode:Monitor"; then
            return 0 # Is in monitor mode
        fi
    fi
    return 1 # Not in monitor mode or doesn't exist
}


# --- Main Script Logic ---

# Ensure log directory exists
mkdir -p "${LOG_DIR}"
touch "${LOG_FILE}" # Ensure log file exists for appending

log_message "INFO" "Monitor mode script started."

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   log_message "ERROR" "This script must be run as root. Please use sudo."
   exit 1
fi

# Determine target wireless interface
TARGET_WLAN_IFACE=""
if [ -n "${1:-}" ]; then
    TARGET_WLAN_IFACE="$1"
    log_message "INFO" "Wireless interface specified as argument: ${TARGET_WLAN_IFACE}"
    # Validate the provided interface name (basic check)
    if ! [[ "${TARGET_WLAN_IFACE}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_message "ERROR" "Invalid interface name provided: '${TARGET_WLAN_IFACE}'. Name should be alphanumeric, underscores, or hyphens."
        exit 1
    fi
    if ! interface_exists_check "${TARGET_WLAN_IFACE}"; then
        log_message "ERROR" "Provided wireless interface '${TARGET_WLAN_IFACE}' does not exist."
        exit 1
    fi
else
    log_message "INFO" "No interface specified. Detecting default wireless interface..."
    # Find first available interface from common names or `iw dev`
    if command -v iw >/dev/null 2>&1; then
        # Get first wireless interface from 'iw dev' that is not already a monitor interface (e.g. mon0, wlan0mon)
        # and is a physical device (not P2P, etc.)
        DETECTED_IFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -Eiv '(mon|p2p|vir)' | head -n 1)
        if [ -n "${DETECTED_IFACE}" ]; then
            TARGET_WLAN_IFACE="${DETECTED_IFACE}"
            log_message "INFO" "Detected wireless interface: ${TARGET_WLAN_IFACE} using 'iw dev'."
        fi
    fi

    if [ -z "${TARGET_WLAN_IFACE}" ]; then # Fallback to candidate list if 'iw dev' failed or not available
        for iface_candidate in "${DEFAULT_IFACE_CANDIDATES[@]}"; do
            if interface_exists_check "${iface_candidate}"; then
                TARGET_WLAN_IFACE="${iface_candidate}"
                log_message "INFO" "Found existing wireless interface from default list: ${TARGET_WLAN_IFACE}"
                break
            fi
        done
    fi

    if [ -z "${TARGET_WLAN_IFACE}" ]; then
        log_message "ERROR" "Could not detect a suitable default wireless interface. Please specify one."
        exit 1
    fi
fi

# Define expected monitor interface name (common convention, airmon-ng might vary)
# Airmon-ng often creates IFACENAMEmon (e.g. wlan0mon). Some older versions/systems might create monX.
# We will primarily rely on airmon-ng's output or check for *any* new monitor interface if exact name fails.
EXPECTED_MON_IFACE="${TARGET_WLAN_IFACE}mon"

log_message "INFO" "Target wireless interface: ${TARGET_WLAN_IFACE}"
log_message "INFO" "Expected monitor interface name after creation: ${EXPECTED_MON_IFACE} (actual name may vary)"

# Idempotence: Check if the *target* interface or *expected monitor* interface is already in monitor mode
if is_monitor_mode_active "${TARGET_WLAN_IFACE}"; then
    log_message "SUCCESS" "Interface '${TARGET_WLAN_IFACE}' is ALREADY in monitor mode."
    exit 0
elif is_monitor_mode_active "${EXPECTED_MON_IFACE}"; then
    log_message "SUCCESS" "Monitor interface '${EXPECTED_MON_IFACE}' ALREADY exists and is in monitor mode."
    exit 0
else
    # Check other common monitor interface names like "mon0" if they were not the target/expected
    if [ "${TARGET_WLAN_IFACE}" != "mon0" ] && [ "${EXPECTED_MON_IFACE}" != "mon0" ] && is_monitor_mode_active "mon0"; then
         log_message "INFO" "A generic monitor interface 'mon0' is already active. If this is not for '${TARGET_WLAN_IFACE}', consider stopping it or specifying a different base interface."
         # Depending on desired behavior, could exit or warn. For now, warn and proceed to create specific one if needed.
    fi
fi


# Kill interfering processes
log_message "INFO" "Running 'airmon-ng check kill' to stop potentially interfering processes..."
if sudo airmon-ng check kill; then
    log_message "INFO" "'airmon-ng check kill' completed."
else
    log_message "WARNING" "'airmon-ng check kill' reported errors or no processes to kill. This is often okay."
fi
sleep 1 # Small pause after check kill

# Start monitor mode
log_message "INFO" "Attempting to start monitor mode on '${TARGET_WLAN_IFACE}' using airmon-ng..."

# Capture airmon-ng output to try and determine the created interface name
AIRMON_OUTPUT_FILE=$(mktemp) # Create a temporary file to store output
if sudo airmon-ng start "${TARGET_WLAN_IFACE}" > "${AIRMON_OUTPUT_FILE}" 2>&1; then
    # Parse output to find the name of the monitor interface created
    # Typical output: "(monitor mode enabled on mon0)" or "(monitor mode enabled on wlan0mon)"
    # Or "phy0  wlan0   Hubsan H107   (monitor mode enabled)" if already enabled (should be caught by earlier check)
    # Or "phy1  wlan1   (monitor mode enabled on wlan1mon)"

    ACTUAL_MON_IFACE_NAME=""
    # Try to parse the common patterns from airmon-ng output
    # Pattern 1: "...enabled on <iface_name>)"
    PARSED_NAME_PATTERN1=$(grep -oP '\(monitor mode enabled on \K[^\)]+' "${AIRMON_OUTPUT_FILE}" | awk '{print $1}')
    # Pattern 2: "...enabled) on <iface_name>" (older airmon-ng or some drivers)
    PARSED_NAME_PATTERN2=$(grep -oP '\(monitor mode enabled\) on \K[^\s]+' "${AIRMON_OUTPUT_FILE}" | awk '{print $1}') # Less common
    # Pattern 3: If the interface itself was put into monitor mode without renaming
    PARSED_NAME_PATTERN3=$(grep -oP "\(${TARGET_WLAN_IFACE}\s+monitor mode enabled\)" "${AIRMON_OUTPUT_FILE}" && echo "${TARGET_WLAN_IFACE}")


    if [ -n "${PARSED_NAME_PATTERN1}" ]; then
        ACTUAL_MON_IFACE_NAME="${PARSED_NAME_PATTERN1}"
    elif [ -n "${PARSED_NAME_PATTERN2}" ]; then
        ACTUAL_MON_IFACE_NAME="${PARSED_NAME_PATTERN2}"
    elif [ -n "${PARSED_NAME_PATTERN3}" ]; then
        ACTUAL_MON_IFACE_NAME="${PARSED_NAME_PATTERN3}"
    else
        # Fallback: if parsing fails, assume the EXPECTED_MON_IFACE or check common ones like mon0, mon1 etc.
        # This part can be tricky as airmon-ng behavior varies.
        log_message "WARNING" "Could not reliably parse monitor interface name from airmon-ng output. Will check common names."
        if is_monitor_mode_active "${EXPECTED_MON_IFACE}"; then
            ACTUAL_MON_IFACE_NAME="${EXPECTED_MON_IFACE}"
        elif is_monitor_mode_active "mon0" && [ "${TARGET_WLAN_IFACE}" != "mon0" ]; then # if mon0 was created and not the base
             ACTUAL_MON_IFACE_NAME="mon0"
        elif is_monitor_mode_active "${TARGET_WLAN_IFACE}"; then # if the original interface was switched to monitor mode
             ACTUAL_MON_IFACE_NAME="${TARGET_WLAN_IFACE}"
        fi
    fi
    rm -f "${AIRMON_OUTPUT_FILE}" # Clean up temp file

    if [ -n "${ACTUAL_MON_IFACE_NAME}" ] && is_monitor_mode_active "${ACTUAL_MON_IFACE_NAME}"; then
        log_message "SUCCESS" "Monitor mode successfully enabled on '${ACTUAL_MON_IFACE_NAME}' (derived from '${TARGET_WLAN_IFACE}')."
        # Optionally, print the name of the monitor interface to stdout for scripting
        # echo "${ACTUAL_MON_IFACE_NAME}"
        exit 0
    else
        log_message "ERROR" "Airmon-ng reported success, but could not confirm active monitor interface '${ACTUAL_MON_IFACE_NAME:-${EXPECTED_MON_IFACE}}' or it's not in monitor mode."
        log_message "INFO" "Please check 'iwconfig' or 'ip link show' to see the current interface status."
        exit 1
    fi
else
    # airmon-ng start command failed
    AirmonLog=$(cat "${AIRMON_OUTPUT_FILE}")
    rm -f "${AIRMON_OUTPUT_FILE}"
    log_message "ERROR" "Failed to enable monitor mode on '${TARGET_WLAN_IFACE}' using airmon-ng."
    log_message "ERROR" "Airmon-ng output: ${AirmonLog}"
    exit 1
fi

log_message "INFO" "Monitor mode script finished."