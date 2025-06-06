README.md

# iNTRUDER v1.5 - Cyberpunk WiFi Pentesting Suite

Welcome to **iNTRUDER v1.5**, an elite-grade WiFi penetration testing dashboard designed for security professionals and ethical hackers. It combines the power of classic Linux wireless tools with a sleek **cyberpunk-styled web interface** for effortless control and visualization.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Available Modules](#available-modules)
- [Dashboard Overview](#dashboard-overview)
- [Troubleshooting](#troubleshooting)
- [Security Disclaimer](#security-disclaimer)
- [License](#license)

---

## Features

- **One-click Monitor Mode Activation**
- **Real-Time WiFi Scanning and Logging**
- **Handshake Capture via `airodump-ng`**
- **Deauthentication Attacks**
- **WPA/WPA2 Handshake Cracking with Wordlists**
- **Web-based Dashboard with Cyberpunk UI**
- Fast, modular, and fully extensible.

---

## Requirements

- OS: **Linux** (Debian-based recommended)
- Terminal emulator (for direct script testing if needed)
- Python 3.8+
- Tools: `aircrack-ng`, `iwconfig`, `ifconfig`, `macchanger`
- Browser: Any modern browser (Chrome, Firefox)

### Python Dependencies

Install using pip:

```bash
pip install flask flask_cors

System Tools

Ensure these tools are installed:

sudo apt update
sudo apt install aircrack-ng macchanger net-tools


---

Installation

Step-by-Step Setup

1. Extract the Project:

unzip iNTRUDER_v1.5.zip && cd iNTRUDER_v1.4


2. Make Scripts Executable:

chmod +x *.sh


3. Run the Backend Server:

python3 server.js


4. Open Dashboard: Visit http://localhost:5000 in your browser.




---

Usage Guide

> IMPORTANT: Run all commands with root privileges unless specified.



1. Start Monitor Mode

Click "Start" in the “Start Monitor Mode” panel.

This activates monitor mode on wlan0.


2. Capture Handshake

Click "Capture" in the “Handshake Capture” panel.

Target AP handshakes will be saved for cracking.


3. Scan & Log Networks

Click "Scan" under “Log Sniffer”.

Detected APs and clients are logged in real time.


4. Deauth Attack

Input:

BSSID (target)

Client MAC (optional)

Interface (default: wlan0mon)


Click "Execute Deauth" to disconnect clients.


5. Crack WPA Handshake

Input:

Path to .cap file

Wordlist path (e.g., /usr/share/wordlists/rockyou.txt)


Click "Crack" to brute force credentials.



---

Available Modules

Module	Script/File	Description

Monitor Mode	start-mon.sh	Starts wlan0 in monitor mode
Network Scanner	scan.sh	Captures live WiFi traffic
Handshake Capture	handshake.py	Extracts WPA/WPA2 handshake
WPA Cracking	wifi_cracker.py	Uses aircrack-ng to crack PSK
Deauth Attack	deauth.py	Sends deauthentication frames



---

Dashboard Overview

Panel	Purpose	API Trigger

Start Monitor	Enables monitor mode	/api/start-monitor
Capture Handshake	Launches handshake capture	/api/handshake
Log Networks	Displays nearby APs	/api/scan-networks
Deauth Attack	Disconnects devices	/api/deauth
Crack WPA	Brute force PSK from capture	/api/crack-wpa



---

Troubleshooting

Common Issues

Problem	Solution

Buttons do nothing	Ensure backend is running: python3 server.js
Output panel is blank	Check browser dev console (F12)
Monitor mode not activating	Verify interface: iwconfig
No networks detected	Ensure you're close to APs and using correct interface
Cracking fails	Use strong wordlists like rockyou.txt or seclists


Debugging Tips

Test scripts manually if needed:

sudo ./start-mon.sh
sudo python3 handshake.py

Log output files:

Logs and .cap files stored in logs/ or captures/ directories (create if missing).




---

Security Disclaimer

This tool is intended strictly for authorized testing of networks you own or have explicit permission to audit. Unauthorized access to computer networks is illegal and unethical.


---

License

MIT License — free to modify and distribute with proper credit to the authors.


---

Contribution

Feel free to fork, submit pull requests, or suggest improvements. We welcome collaboration from fellow security professionals and enthusiasts.
