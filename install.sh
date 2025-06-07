#!/bin/bash

# iNTRUDER v1.5 Installer Script
# Description: Sets up the iNTRUDER v1.5 environment.
# This script must be run with sudo privileges.

set -euo pipefail # Strict mode

LOG_DIR="logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/install_${TIMESTAMP}.log"

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR}"

# Redirect all stdout and stderr to the log file and tee to console
exec > >(tee -a "${LOG_FILE}") 2>&1

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}=== iNTRUDER v1.5 - Automated Installer ===${NC}"
echo -e "${YELLOW}Detailed log: ${LOG_FILE}${NC}"

# Check for sudo/root privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}ERROR: This script must be run as root or with sudo.${NC}"
   exit 1
fi

# OS Detection (Debian/Ubuntu specific)
echo -e "${YELLOW}Detecting operating system...${NC}"
if ! command -v lsb_release >/dev/null || ! lsb_release -d | grep -q -E "Ubuntu|Debian|Kali"; then
    echo -e "${RED}ERROR: This script is intended for Debian-based systems (Ubuntu, Debian, Kali).${NC}"
    echo -e "${RED}If you are on a different system, please install dependencies manually.${NC}"
    exit 1
fi
echo -e "${GREEN}Debian-based system detected.${NC}"

# Step 1: Update system package list
echo -e "${YELLOW}Updating system package list (apt update)...${NC}"
if apt update; then
    echo -e "${GREEN}System package list updated successfully.${NC}"
else
    echo -e "${RED}ERROR: Failed to update system package list.${NC}"
    exit 1
fi

# Step 2: Install core system dependencies
echo -e "${YELLOW}Installing core system dependencies...${NC}"
CORE_DEPS=(
    aircrack-ng
    macchanger
    wireless-tools
    iproute2
    python3
    python3-pip
    python3-venv
    curl # For general utility, often helpful
    unzip # For managing archives if any are added later
)
if apt install -y "${CORE_DEPS[@]}"; then
    echo -e "${GREEN}Core system dependencies installed successfully.${NC}"
else
    echo -e "${RED}ERROR: Failed to install core system dependencies.${NC}"
    exit 1
fi

# Step 3: Install optional system dependencies for advanced plugins
echo -e "${YELLOW}Installing optional system dependencies for advanced plugins...${NC}"
OPTIONAL_DEPS=(
    hostapd
    dnsmasq
    mitmproxy
    reaver
    # sslstrip # sslstrip is often problematic, consider mitmproxy's built-in capabilities or alternatives
)
if apt install -y "${OPTIONAL_DEPS[@]}"; then
    echo -e "${GREEN}Optional system dependencies installed successfully.${NC}"
else
    echo -e "${YELLOW}Warning: Failed to install some optional system dependencies. Advanced plugins might not work.${NC}"
    # Not exiting with error for optional dependencies
fi


# Step 4: Create project directories (captures, reports were created in step 1, logs is already handled)
# Redundant if previous step created them, but good for idempotency if script is re-run partially.
echo -e "${YELLOW}Ensuring project directories exist (captures/, reports/, logs/)...${NC}"
mkdir -p captures reports logs # logs is also created at the top for the log file itself
echo -e "${GREEN}Project directories ensured.${NC}"

# Step 5: Python virtual environment setup
VENV_DIR=".venv"
echo -e "${YELLOW}Setting up Python virtual environment in '${VENV_DIR}'...${NC}"
if [ ! -d "${VENV_DIR}" ]; then
  if python3 -m venv "${VENV_DIR}"; then
    echo -e "${GREEN}Python virtual environment created successfully.${NC}"
  else
    echo -e "${RED}ERROR: Failed to create Python virtual environment.${NC}"
    exit 1
  fi
else
  echo -e "${GREEN}Python virtual environment already exists.${NC}"
fi

# Step 6: Activate virtual environment and install Python dependencies
echo -e "${YELLOW}Activating virtual environment and installing Python dependencies from requirements.txt...${NC}"
# Source venv and install requirements in a subshell to keep environment clean if needed,
# or directly if the script is ending. For robustness:
if source "${VENV_DIR}/bin/activate" && pip install --upgrade pip && pip install -r requirements.txt; then
    echo -e "${GREEN}Python dependencies installed successfully.${NC}"
else
    echo -e "${RED}ERROR: Failed to install Python dependencies.${NC}"
    # Attempt to deactivate in case of failure after activation
    deactivate || true
    exit 1
fi
# Deactivate after successful installation as install script shouldn't leave venv active globally
deactivate || true
echo -e "${GREEN}Virtual environment deactivated.${NC}"


# Step 7: Set executable permissions for specific scripts
SCRIPTS_TO_MAKE_EXECUTABLE=("start-mon.sh") # Add other scripts as needed
echo -e "${YELLOW}Setting executable permissions for scripts: ${SCRIPTS_TO_MAKE_EXECUTABLE[*]}${NC}"
for script_name in "${SCRIPTS_TO_MAKE_EXECUTABLE[@]}"; do
    if [ -f "$script_name" ]; then
        if chmod +x "$script_name"; then
            echo -e "${GREEN}Made '$script_name' executable.${NC}"
        else
            echo -e "${RED}ERROR: Failed to make '$script_name' executable.${NC}"
            # Decide if this is a fatal error
        fi
    else
        echo -e "${YELLOW}Warning: Script '$script_name' not found, skipping chmod.${NC}"
    fi
done

# Final message
echo -e "${GREEN}iNTRUDER v1.5 installation process completed!${NC}"
echo -e "${YELLOW}Please check the log file for details: ${LOG_FILE}${NC}"
echo -e "${CYAN}To run the application:${NC}"
echo -e "${CYAN}1. Activate the virtual environment: source ${VENV_DIR}/bin/activate${NC}"
echo -e "${CYAN}2. Start the server: python -m backend.server (run with sudo if needed for network operations)${NC}"
echo -e "${CYAN}3. Open your browser and navigate to http://localhost:5000 (or configured port).${NC}"
exit 0
