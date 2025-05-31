import logging
import subprocess
import os
import csv
import time
import shutil
import tempfile

from .opsec_utils import MACChanger
from .. import config
from ..core.event_logger import log_event
from ..core.network_utils import interface_exists, is_monitor_mode # Import for interface checks

logger = logging.getLogger(__name__)

class AdaptiveScanner:
    def __init__(self, interface: str):
        logger.info(f"Initializing AdaptiveScanner for interface: {interface}")
        self.interface = interface
        self.mac_changer = MACChanger()
        self.mac_spoofing_active_for_scan = False # Track if MAC was changed by this instance for this scan
        if config.MAC_CHANGE_ENABLED and not self.mac_changer._check_macchanger_installed():
            logger.warning("MAC_CHANGE_ENABLED is True, but macchanger is not found. MAC spoofing for scanner will be disabled for this session.")
            self._mac_changer_available = False
        else:
            self._mac_changer_available = True

    def _parse_airodump_csv(self, csv_filepath: str) -> tuple[list, list]:
        networks = []
        clients = []
        parsing_clients = False

        # Standard airodump-ng CSV headers (approximate, may vary slightly by version)
        # These are simplified for common fields. Add more as needed.
        ap_headers = ["BSSID", "First time seen", "Last time seen", "channel", "Speed", "Privacy", "Cipher", "Authentication", "Power", "# beacons", "# IV", "LAN IP", "ID-length", "ESSID", "Key"]
        client_headers = ["Station MAC", "First time seen", "Last time seen", "Power", "# packets", "BSSID", "Probed ESSIDs"]

        try:
            with open(csv_filepath, 'r', encoding='utf-8', errors='ignore') as f:
                csv_reader = csv.reader(f)
                for row in csv_reader:
                    # Strip whitespace from each cell
                    row = [cell.strip() for cell in row]
                    if not row or not row[0]: # Skip empty lines or lines without a BSSID/Station MAC
                        continue

                    if row[0].strip() == 'BSSID' and 'Station MAC' in row: # Header for client list
                        parsing_clients = True
                        # Update client_headers if needed based on actual file, for robustness
                        # For now, assume our predefined client_headers are sufficient if this line is matched
                        logger.debug("Found client section header in CSV.")
                        continue

                    if not parsing_clients:
                        if row[0].strip() == 'BSSID': # AP section header, skip
                            logger.debug("Found AP section header in CSV.")
                            continue
                        # Map row to dict using ap_headers
                        # Ensure row has enough columns, pad with None if not (though airodump usually fixed width)
                        network_dict = dict(zip(ap_headers, row[:len(ap_headers)] + [None]*(len(ap_headers)-len(row))))
                        if len(network_dict.get("BSSID", "")) >= 17 : # Basic validation for a MAC address
                           networks.append(network_dict)
                    else:
                        # Map row to dict using client_headers
                        client_dict = dict(zip(client_headers, row[:len(client_headers)] + [None]*(len(client_headers)-len(row))))
                        if len(client_dict.get("Station MAC", "")) >= 17: # Basic validation
                            clients.append(client_dict)
            logger.info(f"Parsed {len(networks)} networks and {len(clients)} clients from {csv_filepath}")
        except FileNotFoundError:
            logger.error(f"Airodump-ng output CSV file not found at path: {csv_filepath}")
        except UnicodeDecodeError:
            logger.error(f"Unicode decode error while reading {csv_filepath}. File may contain non-UTF-8 characters.", exc_info=True)
        except csv.Error as e:
            logger.error(f"CSV parsing error for file {csv_filepath}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error parsing CSV file {csv_filepath}: {e}", exc_info=True)
        return networks, clients

    def scan(self, duration_seconds: int = 30, scan_intensity: str = 'normal') -> dict:
        log_event("scan_initiated", {"interface": self.interface, "duration_seconds": duration_seconds, "scan_intensity": scan_intensity})
        logger.info(f"Scan called: duration={duration_seconds}s, intensity='{scan_intensity}', interface='{self.interface}'")

        if not interface_exists(self.interface):
            logger.error(f"Interface {self.interface} does not exist for scan.")
            # Log event for this specific failure
            log_event("scan_failed", {"interface": self.interface, "reason": "Interface does not exist", "duration_seconds": duration_seconds})
            return {"networks": [], "clients": [], "error": f"Interface {self.interface} does not exist."}

        if not is_monitor_mode(self.interface):
            logger.warning(f"Interface {self.interface} is not in monitor mode. Scan may fail or provide limited results.")
            # Log event for this warning, but proceed with scan as per original instruction
            log_event("scan_warning_monitor_mode", {"interface": self.interface, "reason": "Not in monitor mode"})
            # For now, a warning is logged, and scan proceeds.
            # If strict monitor mode is required, uncomment below:
            # return {"networks": [], "clients": [], "error": f"Interface {self.interface} not in monitor mode."}

        temp_dir = None
        original_mac = None
        networks, clients = [], []
        self.mac_spoofing_active_for_scan = False # Reset for this scan attempt

        try:
            temp_dir = tempfile.mkdtemp(prefix="intruder_scan_")
            output_prefix = os.path.join(temp_dir, "scan_out")
            logger.debug(f"Scan output files will be prefixed with: {output_prefix}")

            if config.MAC_CHANGE_ENABLED and self._mac_changer_available:
                logger.info(f"MAC change enabled for scan on {self.interface}.")
                current_mac_before_change = self.mac_changer.get_current_mac(self.interface)
                if current_mac_before_change:
                    original_mac = current_mac_before_change # Store for reversion
                    logger.info(f"Original MAC for {self.interface}: {original_mac}")
                    new_mac, _ = self.mac_changer.set_mac_random(self.interface)
                    if new_mac and new_mac.lower() != original_mac.lower():
                        logger.info(f"Successfully set random MAC for {self.interface} to {new_mac}")
                        self.mac_spoofing_active_for_scan = True
                    elif new_mac:
                         logger.info(f"MAC for {self.interface} is {new_mac}, which was already set or not changed by random attempt.")
                         # Not strictly a new spoof for *this scan's* action, but MAC is non-original or as desired.
                         # We will revert if original_mac is known and different from current.
                         if original_mac.lower() != new_mac.lower():
                            self.mac_spoofing_active_for_scan = True # It is spoofed from original_mac
                    else:
                        logger.warning(f"Failed to set random MAC for {self.interface}. Scanning with current MAC: {original_mac}")
                else:
                    logger.warning(f"Could not get current MAC for {self.interface}. MAC spoofing for scan will be skipped.")
            else:
                logger.info(f"MAC change not enabled or macchanger not available for scan on {self.interface}.")

            # --write-interval 1 is frequent, consider 5 for longer scans if disk I/O is an issue.
            cmd = ["airodump-ng", "--write", output_prefix, "--write-interval", "1", "--output-format", "csv", self.interface]

            logger.info(f"Starting airodump-ng scan: {' '.join(cmd)}")
            process = None
            try:
                # Popen does not accept 'check=True' directly, and we manage errors manually.
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
                logger.info(f"Airodump-ng process started (PID: {process.pid}). Scanning for {duration_seconds} seconds...")

                # Allow airodump-ng to run for the specified duration
                try:
                    # This is a blocking wait, but airodump-ng doesn't self-terminate by duration.
                    # We rely on the terminate() call after a delay.
                    # stdout, stderr = process.communicate(timeout=duration_seconds + 10) # Give extra 10s for graceful exit after duration
                    # The above communicate() would wait for process to end or timeout.
                    # Instead, we sleep then terminate.
                    time.sleep(duration_seconds)
                except KeyboardInterrupt: # Allow manual interruption of scan
                    logger.info("Scan duration interrupted by user.")
                    # Fall through to finally block for termination
                    raise # Re-raise to stop the scan method if desired, or handle differently

            except FileNotFoundError:
                logger.error(f"Command 'airodump-ng' not found. Please ensure aircrack-ng suite is installed.", exc_info=True)
                # No process to terminate or clean up here beyond the main finally block
                return {"networks": [], "clients": [], "error": "airodump-ng not found"}
            except Exception as e_popen:
                logger.error(f"Failed to start airodump-ng process: {e_popen}", exc_info=True)
                return {"networks": [], "clients": [], "error": f"airodump-ng Popen failed: {e_popen}"}
            finally:
                stdout_final, stderr_final = "", ""
                if process and process.poll() is None:
                    logger.info(f"Scan duration ended. Terminating airodump-ng process (PID: {process.pid})...")
                    process.terminate()
                    try:
                        # Wait for process to terminate and get final outputs
                        stdout_final, stderr_final = process.communicate(timeout=15) # Increased timeout for communicate after terminate
                        logger.info(f"Airodump-ng process (PID: {process.pid}) terminated successfully.")
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Airodump-ng process (PID: {process.pid}) did not terminate gracefully after 15s. Killing.")
                        process.kill()
                        try: # Try communicate again after kill
                            stdout_final, stderr_final = process.communicate(timeout=5)
                        except Exception as e_comm_kill:
                             logger.error(f"Error communicating after kill for PID {process.pid}: {e_comm_kill}")
                        logger.info(f"Airodump-ng process (PID: {process.pid}) killed.")
                    except Exception as e_term:
                        logger.error(f"Error during airodump-ng termination/communication: {e_term}", exc_info=True)
                elif process: # Process already exited before terminate was called
                    logger.info(f"Airodump-ng process (PID: {process.pid}) already exited with code: {process.returncode}")
                    # Try to get any remaining output
                    try:
                        stdout_final, stderr_final = process.communicate(timeout=5) # Short timeout
                    except Exception as e_comm_exited:
                        logger.error(f"Error communicating with already exited airodump-ng process {process.pid}: {e_comm_exited}")

                if stdout_final: logger.debug(f"Final airodump-ng stdout: {stdout_final}")
                if stderr_final: logger.debug(f"Final airodump-ng stderr: {stderr_final}")

            csv_filepath = None
            # Airodump-ng typically names the CSV file like 'scan_out-01.csv'
            # List directory and find the most recent CSV if multiple, or the first one.
            # Simple approach: find the first one that matches.
            if os.path.exists(temp_dir):
                for f_name in sorted(os.listdir(temp_dir)): # Sort to get predictable file if multiple (-01, -02)
                    if f_name.startswith(os.path.basename(output_prefix)) and f_name.endswith(".csv"):
                        csv_filepath = os.path.join(temp_dir, f_name)
                        logger.info(f"Found airodump-ng output CSV: {csv_filepath}")
                        break

            if csv_filepath and os.path.exists(csv_filepath):
                networks, clients = self._parse_airodump_csv(csv_filepath)
            else:
                logger.error(f"Airodump-ng output CSV file could not be found starting with prefix '{output_prefix}' in {temp_dir}.")

        except Exception as e: # Catch-all for unexpected errors during setup or Popen
            logger.error(f"An error occurred during the scan setup or execution: {e}", exc_info=True)
        finally:
            if config.MAC_CHANGE_ENABLED and self._mac_changer_available and original_mac and self.mac_spoofing_active_for_scan:
                logger.info(f"Reverting MAC for {self.interface} to {original_mac} after scan.")
                restored_mac, _ = self.mac_changer.revert_to_original_mac(self.interface)
                if restored_mac and restored_mac.lower() == original_mac.lower():
                    logger.info(f"Successfully reverted MAC for {self.interface} to {restored_mac}.")
                else:
                    logger.warning(f"Failed to revert MAC for {self.interface} to {original_mac}. Current MAC: {restored_mac}")
            elif config.MAC_CHANGE_ENABLED and self._mac_changer_available and original_mac and not self.mac_spoofing_active_for_scan:
                logger.info(f"MAC was not actively spoofed by this scan instance for {self.interface} (or failed to spoof), no reversion attempted by scanner. Current MAC: {self.mac_changer.get_current_mac(self.interface)}")


            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    logger.info(f"Successfully removed temporary scan directory: {temp_dir}")
                except Exception as e_rm:
                    logger.error(f"Failed to remove temporary scan directory {temp_dir}: {e_rm}", exc_info=True)
            self.mac_spoofing_active_for_scan = False # Reset status

        return {"networks": networks, "clients": clients}


if __name__ == '__main__':
    # Basic test setup
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    monitor_interface = "wlan0mon" # <--- !!! SET YOUR MONITOR INTERFACE HERE FOR TESTING !!!

    if not os.path.exists(f"/sys/class/net/{monitor_interface}"):
        logger.error(f"Test interface {monitor_interface} does not exist. Configure config.py and ensure interface is in monitor mode.")
    else:
        logger.info(f"Attempting to use interface: {monitor_interface} for scanner test.")
        # Temporarily set MAC_CHANGE_ENABLED for this test run if you want to test it
        # original_mac_setting = config.MAC_CHANGE_ENABLED
        # config.MAC_CHANGE_ENABLED = True # or False

        scanner = AdaptiveScanner(interface=monitor_interface)

        logger.info(f"--- Running scan (MAC Change Currently Configured: {config.MAC_CHANGE_ENABLED}) ---")
        scan_results = scanner.scan(duration_seconds=20)
        logger.info(f"Scan results: {len(scan_results.get('networks',[]))} networks, {len(scan_results.get('clients',[]))} clients found.")

        if scan_results.get('networks'):
            logger.debug("Found Networks:")
            for net in scan_results['networks']:
                logger.debug(f"  ESSID: {net.get('ESSID')}, BSSID: {net.get('BSSID')}, Channel: {net.get('channel')}")
        if scan_results.get('clients'):
            logger.debug("Found Clients:")
            for cli in scan_results['clients']:
                logger.debug(f"  Station MAC: {cli.get('Station MAC')}, BSSID: {cli.get('BSSID')}")

        # config.MAC_CHANGE_ENABLED = original_mac_setting # Restore original setting

    logger.info("--- AdaptiveScanner Test Completed ---")
