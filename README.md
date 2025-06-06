# iNTRUDER v1.5 - Cyberpunk WiFi Pentesting Suite

Welcome to **iNTRUDER v1.5**, an elite-grade WiFi penetration testing dashboard designed for security professionals and ethical hackers. It combines the power of classic Linux wireless tools with a sleek **cyberpunk-styled web interface** for effortless control and visualization via a refactored Python backend.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)
- [Security Disclaimer](#security-disclaimer)
- [License](#license)
- [Contribution](#contribution)

---

## Features

- **One-click Monitor Mode Activation** (via script, configurable interface)
- **Adaptive Network Scanning** (using `airodump-ng`, with structured JSON output)
- **Handshake Capture** via `airodump-ng`
- **Deauthentication Attacks** (via `aireplay-ng`)
- **WPA/WPA2 Handshake Cracking** with Wordlists (via `aircrack-ng`)
- **Configurable MAC Address Spoofing** (via `macchanger`) for relevant operations
- **Centralized JSONL Event Logging** for Auditing and Reporting
- **JSON and Markdown Report Generation** from session events
- Web-based Dashboard with Cyberpunk UI (requires manual update for full compatibility)
- Modular Python backend using Flask and SocketIO.

---

## Requirements

### System
- OS: **Linux** (Debian-based like Kali, Ubuntu recommended)
- Python 3.8+

### Core External Tools
The following tools must be installed and in your system's PATH:
- `aircrack-ng` suite (includes `airodump-ng`, `aireplay-ng`, `aircrack-ng`)
- `macchanger` (for MAC address spoofing)
- `iwconfig` and `ip` (from `wireless-tools` and `iproute2` packages, usually pre-installed on most Linux distros)

### Optional Tools for Advanced Plugins (Functionality present as placeholders)
- `hostapd` and `dnsmasq` (for Rogue AP functionality)
- `mitmproxy` (for MITM proxy features)
- `reaver` (for WPS attacks)
- `sslstrip` (for use with Rogue AP / MITM)

### Python Dependencies
It is highly recommended to use a Python virtual environment.
Install dependencies using `pip` from the project root:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
```
The `requirements.txt` file includes:
- `Flask`
- `Flask-CORS`
- `Flask-SocketIO`
- `eventlet` (for SocketIO production/async mode)

*(Note: Specific versions for the system tools like `aircrack-ng` are not listed, but recent versions are generally expected for compatibility with all features.)*

---

## Installation

1.  **Clone or Download:**
    ```bash
    # git clone <repository_url>
    # cd iNTRUDER_PROJECT_ROOT
    ```
    Or extract the project archive.

2.  **Install System Tools:**
    Refer to your distribution's package manager. Example for Debian/Ubuntu (as used in `install.sh`):
    ```bash
    sudo apt update
    sudo apt install -y aircrack-ng macchanger net-tools python3 python3-pip python3-venv unzip curl xdg-utils hostapd dnsmasq reaver sslstrip
    ```
    *(Note: Some tools like `hostapd`, `dnsmasq`, `reaver`, `sslstrip` are for advanced/optional plugins which might still be under active development or have specific prerequisites.)*

3.  **Set up Python Environment and Install Dependencies:**
    From the project root:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    pip install --upgrade pip
    pip install -r requirements.txt
    ```

4.  **Make Scripts Executable (if needed):**
    The `install.sh` script attempts to set necessary permissions. However, you can manually ensure core utility scripts are executable:
    ```bash
    chmod +x install.sh start-mon.sh
    # Add other scripts if they are intended for direct execution
    ```

5.  **Configure the Application:**
    Review and edit `backend/config.py` to suit your environment (see [Configuration](#configuration) section below). Pay special attention to default interface names and paths.

6.  **Run the Backend Server:**
    From the project root directory:
    ```bash
    python -m backend.server
    ```

7.  **Access the Dashboard:**
    Open your browser and navigate to `http://localhost:5000` (or the configured port).
    **IMPORTANT UI NOTE:** The main dashboard JavaScript (`cyber_hud.js`) interacts with backend API endpoints defined in `backend/server.py`. Significant refactoring of Python modules has occurred. **Crucially, `cyber_hud.js` and the API endpoint implementations in `backend/server.py` must be thoroughly reviewed and synchronized to ensure UI functionality.** Without this, the UI may not function as intended.

---

## Configuration

Key configuration settings are located in `backend/config.py`. Modify these as needed.
Many of these settings can also be overridden using **environment variables**. Refer to the comments within `backend/config.py` for the specific environment variable names (e.g., `INTRUDER_LOG_FILE` for `LOG_FILE`).

Key settings include:
-   `APP_BASE_DIR`: Automatically determined base directory of the application. Paths below are relative to this.
-   `DEFAULT_IFACE`: Default wireless interface (e.g., "wlan0"). Env: `INTRUDER_DEFAULT_IFACE`.
-   `MONITOR_IFACE_SUFFIX`: Suffix for monitor mode interfaces (e.g., "mon"). Env: `INTRUDER_MONITOR_IFACE_SUFFIX`.
-   `LOG_LEVEL`: Logging verbosity (e.g., "DEBUG", "INFO"). Env: `INTRUDER_LOG_LEVEL`.
-   `LOG_FILE`: Path for the main application log (e.g., `logs/intruder.log`). Env: `INTRUDER_LOG_FILE`.
-   `EVENT_LOG_FILE`: Path for the JSONL event log (e.g., `logs/session_events.jsonl`). Env: `INTRUDER_EVENT_LOG_FILE`.
-   `MAC_CHANGE_ENABLED`: `True` or `False` to enable/disable MAC spoofing. Env: `INTRUDER_MAC_CHANGE_ENABLED`.
-   `DEFAULT_WORDLIST`: Path to a default wordlist. Env: `INTRUDER_DEFAULT_WORDLIST`. (Ensure this path is valid for cracking features).
-   `REPORTS_DIR`: Directory for reports (e.g., `reports/`). Env: `INTRUDER_REPORTS_DIR`.
-   `HANDSHAKE_CAPTURE_DIR`: Directory for handshake captures (e.g., `captures/`). Env: `INTRUDER_HANDSHAKE_CAPTURE_DIR`.
-   `AIRCRACK_TIMEOUT`: Default timeout for `aircrack-ng` in seconds. Env: `INTRUDER_AIRCRACK_TIMEOUT`.
-   Paths for optional utility scripts like `SCAN_SH_PATH`, `START_MON_SH_PATH`.

---

## Usage Guide

1.  **Prepare Configuration:** Review and optionally edit `backend/config.py`, or set corresponding environment variables.
2.  **Start Server:** From the project root, after activating the virtual environment:
    ```bash
    python3 -m backend.server
    ```
3.  **Access UI:** Open `http://localhost:5000` (or the configured port).
    *   **CRITICAL UI ALIGNMENT:** The main dashboard JavaScript (`cyber_hud.js`) interacts with backend API endpoints defined in `backend/server.py`. Significant refactoring of Python modules has occurred. **Crucially, `cyber_hud.js` and the API endpoint implementations in `backend/server.py` must be thoroughly reviewed and synchronized to ensure UI functionality.** Without this, the UI may not function as intended.
4.  **Use UI Panels (after UI/API alignment):**
    *   **Start Monitor Mode:** Use the terminal or UI controls to activate monitor mode on your wireless interface.
    *   **Scan Networks:** Enter monitor interface and duration, then scan. Results (JSON) appear in output.
    *   **Capture Handshake:** Provide monitor interface and target SSID/BSSID.
    *   **Deauth Attack:** Provide monitor interface, target BSSID, client MAC (optional), and count.
    *   **Crack Handshake:** Provide path to `.cap` file and wordlist (optional if default is set and valid).
    *   **Generate Reports:** Trigger report generation via its API endpoint (UI button to be added).

---

## API Endpoints

The backend provides the following primary API endpoints (base URL: `http://localhost:5000`):

-   `POST /api/monitor/start`
    *   Body (optional): `{"iface": "wlan0"}`
    *   Starts monitor mode on the specified or default interface using `start-mon.sh`.
-   `POST /api/scan/start`
    *   Body (optional): `{"interface": "wlan0mon", "duration": 30}`
    *   Performs a network scan using `AdaptiveScanner` (airodump-ng).
-   `POST /api/deauth/start`
    *   Body: `{"iface": "wlan0mon", "target_bssid": "XX:XX:XX:XX:XX:XX", "client_mac": "YY:YY:YY:YY:YY:YY" (optional), "count": 10 (optional)}`
    *   Executes a deauthentication attack.
-   `POST /api/handshake/start`
    *   Body: `{"iface": "wlan0mon", "ssid": "TargetSSID" (optional), "bssid": "XX:XX:XX:XX:XX:XX" (optional), "channel": N (optional)}` (Either SSID or BSSID required)
    *   Captures handshakes using `HandshakeCapture` (airodump-ng).
-   `POST /api/crack/start`
    *   Body: `{"handshake_file": "path/to/capture.cap", "wordlist": "path/to/wordlist.txt" (optional)}`
    *   Attempts to crack a handshake using `WifiCracker` (aircrack-ng).
-   `POST /api/reporting/generate`
    *   Generates JSON and Markdown summary reports from logged session events.

(Advanced plugin endpoints like `/api/rogue_ap/*`, `/api/mitm/*`, `/api/wps/*` also exist but correspond to functionalities that are currently placeholders or require specific setup.)

---

## Troubleshooting

-   **UI Buttons Don't Work / Errors:** As stated in the **CRITICAL UI ALIGNMENT** note, `cyber_hud.js` (frontend) and `backend/server.py` (backend API endpoints) must be synchronized. If they are not, UI interactions will likely fail or not produce expected results. Check the browser's developer console (usually F12) for JavaScript errors and network request failures.
-   **"ModuleNotFoundError" or "ImportError":** Ensure you have activated the Python virtual environment (`source venv/bin/activate`) and are running `python3 -m backend.server` from the project's root directory.
-   **Tool Not Found Errors (e.g., `macchanger`, `airodump-ng`, `reaver`):** Verify that all required system tools are installed and their paths are accessible to the user running the script (typically root). Use `which <toolname>` to check.
-   **Permission Denied:** Most operations require root privileges. Run the server with `sudo`.
-   **Monitor Mode Issues:** Check `start-mon.sh` script and ensure your wireless card supports monitor mode. Use `iwconfig` or `ip link show` to verify interface states.
-   **Log Files:** Check `intruder.log` (main app log) and `session_events.jsonl` (structured event log) in the project root for detailed error messages or operational history.

---

## Security Disclaimer

This tool is intended strictly for authorized testing of networks you own or have explicit permission to audit. Unauthorized access to computer networks is illegal and unethical. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

## License

MIT License — free to modify and distribute with proper credit to the authors.

---

## Contribution

Feel free to fork, submit pull requests, or suggest improvements. We welcome collaboration from fellow security professionals and enthusiasts.
[end of README.md]
