#!/bin/bash

# iNTRUDER v1.5 Installer Script
# Author: iNTRUDER Development Team
# Date: $(date +%Y-%m-%d)
# Description: Interactive and user-friendly setup for iNTRUDER v1.5

# Exit on error, treat unset variables as an error, and propagate exit status
set -euo pipefail

# --- Configuration & Variables ---
CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m' # No Color

LOG_DIR="logs"
INSTALL_LOG_FILE="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"
BACKEND_SERVER_LOG="backend_server.log" # Placed in root, can be moved to LOG_DIR if preferred
BACKEND_SERVER_PID_FILE="backend_server.pid" # For checking if server is running
SERVER_PORT=5000 # Default port for the backend server

# --- Helper Functions ---
cleanup() {
    echo -e "${YELLOW}Cleaning up any stray processes...${NC}"
    # Example: kill a process if a PID file exists and process is running
    if [ -f "${BACKEND_SERVER_PID_FILE}" ]; then
        if ps -p "$(cat "${BACKEND_SERVER_PID_FILE}")" > /dev/null; then
            echo "Attempting to stop existing server (PID: $(cat "${BACKEND_SERVER_PID_FILE}"))..."
            kill "$(cat "${BACKEND_SERVER_PID_FILE}")"
            rm -f "${BACKEND_SERVER_PID_FILE}"
        else
            # PID file exists but process not running, remove stale PID file
            rm -f "${BACKEND_SERVER_PID_FILE}"
        fi
    fi
    # Add any other cleanup tasks here
}

# Trap EXIT signal to run cleanup function
trap cleanup EXIT

# --- Main Installation Logic ---
echo -e "${CYAN}=== iNTRUDER v1.5 - Automated Installer ===${NC}"

# Ensure log directory exists for the installer log itself
mkdir -p "${LOG_DIR}"
# Tee all output of the script to a log file
exec &> >(tee -a "${INSTALL_LOG_FILE}")

echo -e "${GREEN}Installer output is being logged to: ${INSTALL_LOG_FILE}${NC}"

# Confirm sudo access
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}ERROR: Please run this script as root using: sudo ./install.sh${NC}"
   exit 1
fi

# Step 1: Update system
echo -e "${YELLOW}Step 1: Updating system package lists and upgrading installed packages...${NC}"
apt update && apt upgrade -y

# Step 2: Install required tools
echo -e "${YELLOW}Step 2: Installing core dependencies...${NC}"
# Using python3-pip explicitly. python3-venv is good practice.
apt install -y aircrack-ng macchanger net-tools python3 python3-pip python3-venv unzip curl xdg-utils

# Step 3: Set executable permissions for necessary scripts
echo -e "${YELLOW}Step 3: Setting script permissions...${NC}"
# List known scripts that need execution permission. Avoid blanket chmod on *.sh.
chmod +x install.sh # This script itself
# Assuming other utility scripts are in a 'scripts' subdirectory or specific known locations
# Example: chmod +x scripts/*.sh
# For now, let's list known executable Python CLIs if they exist at root, or specific scripts
# chmod +x log_sniffer.py mitm.py rogue_ap.py wifi_cracker.py wps_attack.py # If these are CLI tools
# If there are scripts in the root that need it:
if [ -f "scan.sh" ]; then chmod +x scan.sh; fi
if [ -f "start-mon.sh" ]; then chmod +x start-mon.sh; fi
# If Python modules are intended to be executable CLI tools:
# find backend -name "*.py" -exec chmod +x {} \; # This is too broad, be specific if needed.


# Step 4: Create log and capture directories if missing (LOG_DIR already created for installer log)
echo -e "${YELLOW}Step 4: Creating application data directories (captures, reports)...${NC}"
mkdir -p captures reports "${LOG_DIR}" # LOG_DIR creation is idempotent

# Step 5: Python virtual environment setup
VENV_DIR="venv"
if [ ! -d "${VENV_DIR}" ]; then
  echo -e "${YELLOW}Step 5: Setting up Python virtual environment in '${VENV_DIR}'...${NC}"
  python3 -m venv "${VENV_DIR}"
else
  echo -e "${GREEN}Step 5: Python virtual environment '${VENV_DIR}' already exists. Skipping creation.${NC}"
fi

echo -e "${YELLOW}Activating virtual environment and installing/upgrading Python packages...${NC}"
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate" # Use source explicitly
pip3 install --upgrade pip # Use pip3 explicitly
pip3 install flask flask_cors flask-socketio
# Consider adding other dependencies from a requirements.txt if available:
# if [ -f "requirements.txt" ]; then pip3 install -r requirements.txt; fi

# Step 6: Backend confirmation
echo -e "${YELLOW}Step 6: Confirming backend server file presence...${NC}"
if [ ! -f backend/server.py ]; then
  echo -e "${RED}ERROR: backend/server.py not found. Cannot start the server. Aborting.${NC}"
  exit 1
fi
echo -e "${GREEN}Backend server file found.${NC}"

# Step 7: Start backend server
echo -e "${YELLOW}Step 7: Starting backend Flask server...${NC}"

# Check if server is already running on the specified port
# Using ss as it's more modern than netstat. Fallback to netstat if ss not found.
SERVER_RUNNING_CHECK_CMD=""
if command -v ss >/dev/null 2>&1; then
    SERVER_RUNNING_CHECK_CMD="ss -tulnp | grep ':${SERVER_PORT}'"
elif command -v netstat >/dev/null 2>&1; then
    SERVER_RUNNING_CHECK_CMD="netstat -tulnp | grep ':${SERVER_PORT}'"
fi

if [ -n "$SERVER_RUNNING_CHECK_CMD" ] && eval "$SERVER_RUNNING_CHECK_CMD" > /dev/null; then
    echo -e "${GREEN}Backend server appears to be already running on port ${SERVER_PORT}.${NC}"
    echo -e "${YELLOW}Skipping server start. If you want to restart it, please stop the existing instance first.${NC}"
else
    echo -e "${YELLOW}Server output will be logged to ${BACKEND_SERVER_LOG}${NC}"
    # The nohup command needs to run in a subshell that has the venv activated.
    # Storing PID for potential management.
    nohup bash -c "source ./${VENV_DIR}/bin/activate && export PYTHONPATH=\$(pwd):\${PYTHONPATH} && python3 -m backend.server" > "${BACKEND_SERVER_LOG}" 2>&1 &
    SERVER_PID=$!
    echo "${SERVER_PID}" > "${BACKEND_SERVER_PID_FILE}"
    echo -e "${YELLOW}Giving the server a moment to start (PID: ${SERVER_PID})...${NC}"
    # Instead of a fixed sleep, a more robust check would be to curl a health endpoint.
    # For simplicity in this script, we'll keep sleep but note its limitation.
    sleep 8 # Increased sleep slightly, but this is still just a best-effort wait.

    if ps -p "${SERVER_PID}" > /dev/null; then
        echo -e "${GREEN}The backend server has been started in the background (PID: ${SERVER_PID}).${NC}"
    else
        echo -e "${RED}ERROR: The backend server failed to start. Check ${BACKEND_SERVER_LOG} for details.${NC}"
        rm -f "${BACKEND_SERVER_PID_FILE}" # Remove PID file as server didn't start
        # No exit here, user might want to check logs and try manually.
    fi
    echo -e "${YELLOW}Check ${CYAN}${BACKEND_SERVER_LOG}${YELLOW} for detailed output or errors.${NC}"
    echo -e "${YELLOW}You can check if the server is running with: ${CYAN}ps aux | grep '[p]ython3 -m backend.server'${NC} or by checking port ${SERVER_PORT}.${NC}"
fi

# Deactivating venv is good practice if the script did other things outside venv scope later.
# For this script, it's the last Python-related action.
# deactivate # Not strictly necessary as script will exit.

# Step 8: Launch dashboard
echo -e "${YELLOW}Step 8: Launching dashboard in your default browser...${NC}"
sleep 2 # Brief pause before trying to open URL

DASHBOARD_URL="http://localhost:${SERVER_PORT}"
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${DASHBOARD_URL}"
else
    echo -e "${YELLOW}Warning: 'xdg-open' command not found.${NC}"
    echo -e "${YELLOW}Please manually open your web browser and navigate to: ${CYAN}${DASHBOARD_URL}${NC}"
fi

# Final message
echo -e "\n${GREEN}=== iNTRUDER v1.5 Installation Summary ===${NC}"
echo -e "${GREEN}Setup process completed.${NC}"
echo -e "${CYAN}Backend server status can be checked in '${BACKEND_SERVER_LOG}' (PID in '${BACKEND_SERVER_PID_FILE}' if started by this script).${NC}"
echo -e "${CYAN}Access the iNTRUDER dashboard via: ${GREEN}${DASHBOARD_URL}${NC}"
echo -e "${YELLOW}Ensure your wireless interface is in monitor mode for full functionality.${NC}"
echo -e "${YELLOW}Refer to documentation for usage and troubleshooting.${NC}"
echo -e "${GREEN}Installation complete. Enjoy using iNTRUDER!${NC}"