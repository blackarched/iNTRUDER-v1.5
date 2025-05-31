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
Install using pip from the project root:
```bash
pip install -r requirements.txt
```
(Note: A `requirements.txt` file should be created containing Flask, Flask-CORS, Flask-SocketIO, and eventlet/gevent if specific async mode is preferred for SocketIO. For this project, the following are key:)
- `Flask`
- `Flask-CORS`
- `Flask-SocketIO`
- `eventlet` (recommended for SocketIO production use)

---

## Installation

1.  **Clone or Download:**
    ```bash
    # git clone <repository_url>
    # cd iNTRUDER_PROJECT_ROOT
    ```
    Or extract the project archive.

2.  **Install System Tools:**
    Refer to your distribution's package manager. Example for Debian/Ubuntu:
    ```bash
    sudo apt update
    sudo apt install -y aircrack-ng macchanger wireless-tools iproute2 hostapd dnsmasq mitmproxy reaver sslstrip
    ```

3.  **Install Python Dependencies:**
    (Assuming a `requirements.txt` with `Flask`, `Flask-CORS`, `Flask-SocketIO`, `eventlet`)
    ```bash
    pip install Flask Flask-CORS Flask-SocketIO eventlet
    ```

4.  **Make Scripts Executable (if needed):**
    Ensure helper shell scripts like `start-mon.sh` are executable:
    ```bash
    chmod +x start-mon.sh
    ```
    (Note: `scan.sh` is now legacy, replaced by internal `AdaptiveScanner`.)

5.  **Configure the Application:**
    Edit `backend/config.py` to suit your environment (see [Configuration](#configuration) section below).

6.  **Run the Backend Server:**
    From the project root directory:
    ```bash
    python -m backend.server
    ```

7.  **Access the Dashboard:**
    Open your browser and navigate to `http://localhost:5000` (or the configured port).
    **IMPORTANT UI NOTE:** The `script.js` for the web interface needs a manual update to align with the latest backend APIs. Refer to `PRODUCTION_CHECKLIST.md` for details.

---

## Configuration

Key configuration settings are located in `backend/config.py`. Modify these as needed:

-   `DEFAULT_IFACE`: Default wireless interface to use (e.g., "wlan0").
-   `MONITOR_IFACE_SUFFIX`: Suffix expected for monitor mode interfaces (e.g., "mon").
-   `LOG_LEVEL`: Logging verbosity (e.g., "INFO", "DEBUG").
-   `LOG_FILE`: Path for the main application log (e.g., "intruder.log").
-   `MAC_CHANGE_ENABLED`: Set to `True` or `False` to enable/disable MAC spoofing globally.
-   `DEFAULT_WORDLIST`: Path to a default wordlist for cracking. Default is `None` (user must provide).
-   `EVENT_LOG_FILE`: Path for the JSONL event log (e.g., "session_events.jsonl").
-   `REPORTS_DIR`: Directory to save generated reports (e.g., "reports/").
-   `AIRCRACK_TIMEOUT`: Default timeout for `aircrack-ng` process in seconds.
-   `START_MON_SH_PATH`: Path to the script used to enable monitor mode.

---

## Usage Guide

1.  **Prepare Configuration:** Edit `backend/config.py` first.
2.  **Start Server:** Run `python -m backend.server`.
3.  **Access UI:** Open `http://localhost:5000`.
    *   **CRITICAL:** The UI (`script.js`) requires a manual update to match the new backend API. Without this, the UI buttons will not work correctly. See `PRODUCTION_CHECKLIST.md`.
4.  **Use UI Panels (after `script.js` update):**
    *   **Start Monitor Mode:** Enter base interface if different from default, then start.
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

-   **UI Buttons Don't Work / Errors:** Ensure `script.js` has been manually updated as per `PRODUCTION_CHECKLIST.md`.
-   **"ModuleNotFoundError" or "ImportError":** Ensure you are running `python -m backend.server` from the project root directory.
-   **Tool Not Found Errors (e.g., `macchanger`, `airodump-ng`):** Verify that all required system tools are installed and in your system's PATH.
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
