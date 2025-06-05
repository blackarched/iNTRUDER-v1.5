#!/bin/bash

# iNTRUDER v1.4 Installer Script
# Author: [Your Name]
# Date: 2025
# Description: Interactive and user-friendly setup for iNTRUDER v1.4

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

echo -e "${CYAN}=== iNTRUDER v1.5 - Automated Installer ===${NC}"

# Confirm sudo access
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Please run this script as root using: sudo ./install.sh${NC}"
   exit 1
fi

# Step 1: Update system
echo -e "${YELLOW}Updating system...${NC}"
apt update && apt upgrade -y

# Step 2: Install required tools
echo -e "${YELLOW}Installing dependencies...${NC}"
apt install -y aircrack-ng macchanger net-tools python3 python3-pip python3-venv unzip curl

# Step 3: Set executable permissions
echo -e "${YELLOW}Setting script permissions...${NC}"
chmod +x *.sh

# Step 4: Create log and capture directories if missing
echo -e "${YELLOW}Creating log directories...${NC}"
mkdir -p logs captures

# Step 5: Python virtual environment setup
if [ ! -d "venv" ]; then
  echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
  python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install flask flask_cors flask-socketio mitmproxy

# Step 6: Backend confirmation
if [ ! -f backend/server.py ]; then
  echo -e "${RED}Error: backend/server.py not found. Aborting.${NC}"
  exit 1
fi

# Step 7: Start backend server
echo -e "${GREEN}Backend ready. Starting Flask server in the background...${NC}"
echo -e "${YELLOW}Server output will be logged to backend_server.log${NC}"
# Ensure venv is activated for this command if not globally for the script part
source venv/bin/activate
nohup python3 -m backend.server > backend_server.log 2>&1 &
echo -e "${YELLOW}Giving the server a moment to start...${NC}"
sleep 5
echo -e "${YELLOW}The backend server has been started in the background.${NC}"
echo -e "${YELLOW}Check ${CYAN}backend_server.log${YELLOW} for detailed output or errors.${NC}"
echo -e "${YELLOW}You can check if the server is running with: ${CYAN}ps aux | grep 'python3 -m backend.server'${NC}"
# Deactivate venv if only activated for this step - though source venv/bin/activate earlier should persist for script
# deactivate # Optional: if you want to explicitly deactivate

# Step 8: Launch dashboard
echo -e "${YELLOW}Launching dashboard in your default browser...${NC}"
sleep 2
xdg-open http://localhost:5000

# Final message
echo -e "${GREEN}iNTRUDER v1.5 successfully installed and running!${NC}"
echo -e "${CYAN}Access it via: http://localhost:5000${NC}"
echo -e "${CYAN}Monitor mode, scans, attacks, and cracking modules are ready.${NC}"