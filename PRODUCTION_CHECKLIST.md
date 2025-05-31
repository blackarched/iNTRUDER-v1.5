# iNTRUDER v1.5 - Production Deployment & Operational Checklist

This checklist is intended for operators deploying or using iNTRUDER v1.5 in a live (but authorized and ethical) penetration testing environment.

## I. Pre-Flight Checks & Setup

**Environment:**
- [ ] **Dedicated Testing Machine:** iNTRUDER is run on a machine dedicated to the pentest, preferably a Kali Linux or similar Debian-based distribution.
- [ ] **Physical Security:** Ensure the testing machine is physically secure.
- [ ] **Network Isolation (Initial):** Understand the network environment. If necessary, start with an isolated setup before connecting to the target network.
- [ ] **Legal Authorization:** Written permission and clear scope for the penetration test are obtained and understood.
- [ ] **Time Synchronization:** System time is accurate (e.g., synced with NTP) for correct timestamping in logs.

**Software & Dependencies:**
- [ ] **OS Updated:** `sudo apt update && sudo apt upgrade -y`
- [ ] **Core Tools Installed:**
    - [ ] `aircrack-ng` suite (airodump-ng, aireplay-ng, aircrack-ng)
    - [ ] `macchanger`
    - [ ] `wireless-tools` (iwconfig)
    - [ ] `iproute2` (ip command)
- [ ] **Optional Advanced Plugin Tools (if their functionality is intended to be used):**
    - [ ] `hostapd`, `dnsmasq`
    - [ ] `mitmproxy`
    - [ ] `reaver`
    - [ ] `sslstrip`
- [ ] **Python Version:** Python 3.8+ confirmed.
- [ ] **Python Dependencies Installed** (from project root, ideally in a virtual environment):
    ```bash
    pip install Flask Flask-CORS Flask-SocketIO eventlet
    ```
    (Or `pip install -r requirements.txt` if provided)
- [ ] **Project Files:** Latest version of iNTRUDER v1.5 is deployed in a known location (e.g., `/opt/iNTRUDER`).
- [ ] **Script Permissions:** `start-mon.sh` is executable (`chmod +x start-mon.sh`).
- [ ] **CRITICAL UI SCRIPT UPDATE:** Ensure `script.js` in the `frontend/` (or `static/`) directory has been **manually updated** with the version provided in the development subtask report for "Basic UI Integration Check & Update". The old `script.js` will not work with the current backend.

## II. Configuration (`backend/config.py`)

- [ ] **Review All Settings:** Open `backend/config.py` and review every parameter.
- [ ] **`DEFAULT_IFACE`:** Set to the primary wireless interface intended for monitoring/attacks (e.g., `wlan0`, `wlxXXXXXXXXXXXX`).
- [ ] **`MONITOR_IFACE_SUFFIX`:** Matches what `start-mon.sh` (or `airmon-ng`) typically appends (e.g., `mon`).
- [ ] **`LOG_LEVEL`:** Set appropriately (`INFO` for normal operations, `DEBUG` for troubleshooting).
- [ ] **`LOG_FILE`:** Path is writable and suitable (default: `intruder.log` in project root).
- [ ] **`MAC_CHANGE_ENABLED`:** Set to `True` if MAC spoofing is desired and authorized for the engagement. `False` otherwise.
- [ ] **`DEFAULT_WORDLIST`:**
    - If a common wordlist is to be used by default, set its absolute path here.
    - Ensure the path is correct and the file is readable by the user running the server.
    - If `None` (default), wordlists must be provided in API calls to `/api/crack/start`.
- [ ] **`EVENT_LOG_FILE`:** Path is writable (default: `session_events.jsonl` in project root).
- [ ] **`REPORTS_DIR`:** Path is writable (default: `reports/` in project root).
- [ ] **`AIRCRACK_TIMEOUT`:** Review default (3600s) and adjust if significantly longer/shorter cracking times are expected.
- [ ] **Script Paths (`START_MON_SH_PATH`):** Verify paths are correct if scripts are moved from project root.

## III. Running the Application

- [ ] **Navigate to Project Root:** `cd /path/to/iNTRUDER_PROJECT_ROOT`
- [ ] **Use `sudo`:** The backend server must be run with root privileges for WiFi operations.
    ```bash
    sudo python -m backend.server
    ```
- [ ] **Verify Server Start:**
    - [ ] Check console output for successful startup messages from Flask/SocketIO.
    - [ ] Check for any errors reported by `validate_config()` at startup. Address these before proceeding.
    - [ ] Note the URL and port (e.g., `http://0.0.0.0:5000/`).
- [ ] **Access UI:** Open a web browser on a machine that can reach the server (if on a remote machine, ensure firewall allows access to the port) and navigate to the server's address.

## IV. Operational Procedures

- [ ] **Monitor Mode First:** Always start monitor mode on an appropriate interface via the UI before attempting scans or attacks that require it. Verify success in UI/logs.
- [ ] **Interface Naming:** Pay attention to interface names. `start-mon.sh` might create `wlan0mon` from `wlan0`. Use the correct monitor interface name in subsequent operations.
- [ ] **Logging:**
    - Monitor `intruder.log` for operational messages and errors.
    - `session_events.jsonl` will record key actions for later reporting.
- [ ] **Handshake Files:** Note where handshake `.cap` files are saved (default: `captures/` directory in project root, or as specified by `HandshakeCapture` module if changed).
- [ ] **Report Generation:** Use the `/api/reporting/generate` endpoint (e.g., via `curl` or a dedicated UI button if added) to create JSON and Markdown reports.
    ```bash
    # Example curl command to trigger report generation:
    curl -X POST http://localhost:5000/api/reporting/generate
    ```
    Generated reports are saved in the `reports/` directory by default.

## V. OPSEC & Best Practice Reminders

- [ ] **Scope Adherence:** Strictly adhere to the authorized scope of the penetration test. Do not target systems or data outside this scope.
- [ ] **Minimize Impact:** Be mindful of potential disruption. Deauthentication attacks are noisy and disruptive. Perform them judiciously.
- [ ] **MAC Spoofing:** If enabled, ensure it's appropriate for the engagement. Reverting to original MAC is handled by some tools, but verify.
- [ ] **Data Handling:** Securely store any captured data (handshakes, logs, reports) according to engagement rules and data privacy best practices. Delete or sanitize data appropriately post-engagement.
- [ ] **Stealth (if required):** This tool is not primarily designed for stealth. Many actions are inherently noisy. Consider this if stealth is a requirement.

## VI. Stopping & Cleanup

- [ ] **Stop Active Modules:** If possible, use UI controls to stop any active modules (e.g., Rogue AP, MITM proxy – though UI for these is not primary focus of current tool state).
- [ ] **Shutdown Server:** Press `Ctrl+C` in the terminal where the server is running.
    - [ ] The `shutdown_handler` should attempt to clean up active services (e.g., stop Rogue AP if it was running). Monitor logs for this.
- [ ] **Verify Interface State:** After stopping, check that wireless interfaces are returned to a normal (managed) mode. If `start-mon.sh` created a monitor interface, it may need to be manually deleted (e.g., `sudo airmon-ng stop wlan0mon` or `sudo ip link delete wlan0mon`).
- [ ] **MAC Address:** If MAC spoofing was used, verify the MAC address has been reverted to its permanent hardware address. `MACChanger` attempts this, but manual verification (`macchanger -s <interface>`) is good practice.
- [ ] **Secure/Delete Artifacts:** Process or delete logs (`intruder.log`, `session_events.jsonl`), captures (`captures/`), and reports (`reports/`) as per engagement policy.

---
This checklist provides a baseline. Adapt and expand it based on specific engagement requirements and organizational policies.
[end of PRODUCTION_CHECKLIST.md]
