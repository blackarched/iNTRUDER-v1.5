import logging
import subprocess
import re
# Adjust the import based on the final location of config if this were a real multi-level package.
# For the current flat backend structure where server.py imports backend.config,
# and opsec_utils.py is in backend.plugins, this needs to be:
from .. import config
from ..core.event_logger import log_event
from ..core.network_utils import interface_exists # Import for interface check

logger = logging.getLogger(__name__)

class MACChanger:
    def __init__(self):
        if not self._check_macchanger_installed():
            logger.error("macchanger command not found. MACChanger utility will not function.")
            # You could raise an exception here or let it fail when methods are called.
            # For now, logging an error. Methods will likely fail with FileNotFoundError.
            # raise RuntimeError("macchanger command not found.")
            pass


    def _check_macchanger_installed(self) -> bool:
        """Checks if macchanger is installed and executable."""
        try:
            process = subprocess.run(['macchanger', '--version'], capture_output=True, text=True, check=True)
            logger.info(f"macchanger detected: {process.stdout.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.debug(f"Failed to run 'macchanger --version': {e}")
            return False

    def _run_command(self, command_args: list[str], check_errors: bool = True, timeout: int = 10) -> tuple[bool, str, str]:
        """
        Helper method to run subprocess commands.
        Returns: tuple (success: bool, stdout_str: str, stderr_str: str)
        """
        success = False
        stdout_str = ""
        stderr_str = ""
        try:
            logger.info(f"Executing command: {' '.join(command_args)}")
            process = subprocess.run(command_args, capture_output=True, text=True, check=check_errors, timeout=timeout)
            stdout_str = process.stdout.strip() if process.stdout else ""
            stderr_str = process.stderr.strip() if process.stderr else ""

            if process.returncode == 0:
                success = True
                if stdout_str: logger.debug(f"Command stdout: {stdout_str}")
                if stderr_str: logger.debug(f"Command stderr (often informational): {stderr_str}") # Changed to debug for non-erroring stderr
            else: # Should only be reached if check_errors=False and it's a non-zero exit
                logger.warning(f"Command '{' '.join(command_args)}' exited with code {process.returncode}.")
                if stdout_str: logger.warning(f"Stdout: {stdout_str}")
                if stderr_str: logger.warning(f"Stderr: {stderr_str}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{' '.join(e.cmd)}' failed with code {e.returncode}", exc_info=True)
            stdout_str = e.stdout.strip() if e.stdout else ""
            stderr_str = e.stderr.strip() if e.stderr else ""
            logger.error(f"Stderr: {stderr_str}")
            logger.error(f"Stdout: {stdout_str}")
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command '{' '.join(e.cmd)}' timed out after {timeout}s.", exc_info=True)
            stdout_str = e.stdout.strip() if e.stdout else ""
            stderr_str = e.stderr.strip() if e.stderr else ""
            if stdout_str: logger.error(f"Partial stdout on timeout: {stdout_str}")
            if stderr_str: logger.error(f"Partial stderr on timeout: {stderr_str}")
        except FileNotFoundError:
            logger.error(f"Command '{command_args[0]}' not found. Is it installed and in PATH?", exc_info=True)
            stderr_str = f"Command '{command_args[0]}' not found."
        except Exception as e:
            logger.error(f"An unexpected error occurred running command '{' '.join(command_args)}'", exc_info=True)
            stderr_str = str(e)

        return success, stdout_str, stderr_str

    def _bring_interface_down(self, interface: str) -> bool:
        logger.info(f"Bringing interface {interface} down.")
        success, _, _ = self._run_command(['ip', 'link', 'set', 'dev', interface, 'down'])
        return success

    def _bring_interface_up(self, interface: str) -> bool:
        logger.info(f"Bringing interface {interface} up.")
        success, _, _ = self._run_command(['ip', 'link', 'set', 'dev', interface, 'up'])
        return success

    def _parse_macchanger_output(self, output: str) -> tuple[str | None, str | None]:
        """Parses macchanger output for Current, Permanent, and New MAC addresses."""
        current_mac, permanent_mac, new_mac = None, None, None

        current_match = re.search(r"Current MAC:\s*([0-9A-Fa-f:]{17})", output)
        if current_match:
            current_mac = current_match.group(1)
            logger.debug(f"Parsed Current MAC: {current_mac}")

        permanent_match = re.search(r"Permanent MAC:\s*([0-9A-Fa-f:]{17})", output)
        if permanent_match:
            permanent_mac = permanent_match.group(1)
            logger.debug(f"Parsed Permanent MAC: {permanent_mac}")

        # "New MAC" can sometimes be followed by "(unknown)" or a vendor.
        # We only care about the MAC address itself.
        new_match = re.search(r"New MAC:\s*([0-9A-Fa-f:]{17})", output)
        if new_match:
            new_mac = new_match.group(1)
            logger.debug(f"Parsed New MAC: {new_mac}")

        # If new_mac was found, it's the most relevant "current" MAC after a change
        return new_mac if new_mac else current_mac, permanent_mac


    def get_current_mac(self, interface: str) -> str | None:
        if not interface_exists(interface):
            logger.error(f"Interface {interface} does not exist. Cannot get MAC address.")
            return None
        logger.info(f"Getting current MAC for {interface}.")
        success, stdout_str, _ = self._run_command(['macchanger', '-s', interface], check_errors=False)
        if success or "Permanent MAC" in stdout_str:
            current, _ = self._parse_macchanger_output(stdout_str)
            return current
        logger.warning(f"Failed to get current MAC for {interface} or parse output. stdout: {stdout_str}")
        return None

    def set_mac_random(self, interface: str) -> tuple[str | None, str | None]:
        if not interface_exists(interface):
            logger.error(f"Interface {interface} does not exist. Cannot set random MAC.")
            return None, None
        logger.info(f"Attempting to set random MAC for {interface}.")
        original_mac = self.get_current_mac(interface) # Get current MAC before changing
        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface):
                interface_was_brought_down = True
            else:
                logger.warning(f"Continuing to attempt MAC change for {interface} despite failure to bring it down first.")

            success, stdout_str, _ = self._run_command(['macchanger', '-r', interface])

            if success and stdout_str:
                new_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if new_mac:
                    logger.info(f"Successfully set random MAC for {interface} to {new_mac} (Permanent: {perm_mac}). Original was: {original_mac}")
                    log_event("mac_address_changed", {"interface": interface, "old_mac": original_mac, "new_mac": new_mac, "permanent_mac": perm_mac, "method": "random"})
                else: # macchanger command succeeded but output parsing failed
                    logger.warning(f"Could not parse new MAC from macchanger -r output for {interface}. Output: {stdout_str}")
                return new_mac, perm_mac

            logger.error(f"Failed to set random MAC for {interface}. macchanger command stdout: {stdout_str}")
            return None, None
        finally:
            if interface_was_brought_down or not interface_exists(interface): # Attempt to bring up if we brought it down, or if it's unexpectedly down
                if not self._bring_interface_up(interface):
                    logger.error(f"CRITICAL: Interface {interface} was left down after set_mac_random attempt.")
                else:
                    logger.info(f"Interface {interface} brought back up after set_mac_random attempt.")
            elif self._is_interface_up(interface): # Check if it's already up if we didn't bring it down
                 logger.debug(f"Interface {interface} is already up after set_mac_random attempt.")
            else: # If it's down and we didn't bring it down, it might be an issue.
                 logger.warning(f"Interface {interface} is unexpectedly down after set_mac_random and was not managed by this method.")


    def _is_interface_up(self, interface: str) -> bool:
        """Helper to check if interface is operationally up."""
        if not interface_exists(interface): return False
        # This is a simplified check. `ip link show <iface>` output contains 'state UP' or 'state DOWN' etc.
        # For brevity, assuming if it exists and macchanger didn't error out majorly, it's likely up or can be brought up.
        # A more robust check would parse `ip link show` state.
        # For now, this is a placeholder if more detailed check is needed.
        # This method is not strictly required if _bring_interface_up is called in finally.
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True)
            if result.returncode == 0 and "state UP" in result.stdout:
                return True
        except Exception:
            pass # Fall through to false
        return False


    def set_mac_specific(self, interface: str, new_mac_address: str) -> tuple[str | None, str | None]:
        logger.info(f"Attempting to set MAC for {interface} to {new_mac_address}.")
        if not interface_exists(interface): # Check added here for consistency, though get_current_mac would also check
            logger.error(f"Interface {interface} does not exist. Cannot set specific MAC.")
            return None, None
        original_mac = self.get_current_mac(interface)
        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface):
                interface_was_brought_down = True
            else:
                logger.warning(f"Continuing to attempt MAC change for {interface} to {new_mac_address} despite failure to bring it down first.")

            success, stdout_str, _ = self._run_command(['macchanger', '-m', new_mac_address, interface])

            if success and stdout_str:
                changed_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if changed_mac and changed_mac.lower() == new_mac_address.lower():
                    logger.info(f"Successfully set MAC for {interface} to {changed_mac} (Permanent: {perm_mac}). Original was: {original_mac}")
                    log_event("mac_address_changed", {"interface": interface, "old_mac": original_mac, "new_mac": changed_mac, "permanent_mac": perm_mac, "method": "specific"})
                elif changed_mac:
                    logger.warning(f"MAC for {interface} changed to {changed_mac}, not the requested {new_mac_address}. Permanent: {perm_mac}. Original was: {original_mac}")
                    log_event("mac_address_changed_unexpected", {"interface": interface, "old_mac": original_mac, "requested_mac": new_mac_address, "actual_new_mac": changed_mac, "permanent_mac": perm_mac, "method": "specific"})
                else: # macchanger command succeeded but output parsing failed
                    logger.warning(f"Could not parse new MAC from macchanger -m output for {interface}. Output: {stdout_str}")
                return changed_mac, perm_mac

            logger.error(f"Failed to set MAC for {interface} to {new_mac_address}. macchanger command stdout: {stdout_str}")
            return None, None
        finally:
            if interface_was_brought_down or not self._is_interface_up(interface): # Check _is_interface_up as a fallback
                if not self._bring_interface_up(interface):
                    logger.error(f"CRITICAL: Interface {interface} was left down after set_mac_specific attempt.")
                else:
                    logger.info(f"Interface {interface} brought back up after set_mac_specific attempt.")
            elif self._is_interface_up(interface):
                 logger.debug(f"Interface {interface} is already up after set_mac_specific attempt.")
            else:
                 logger.warning(f"Interface {interface} is unexpectedly down after set_mac_specific and was not managed by this method.")


    def revert_to_original_mac(self, interface: str) -> tuple[str | None, str | None]:
        logger.info(f"Attempting to revert MAC for {interface} to permanent hardware MAC.")
        if not interface_exists(interface): # Check added here
            logger.error(f"Interface {interface} does not exist. Cannot revert MAC.")
            return None, None
        current_mac_before_revert = self.get_current_mac(interface)
        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface):
                interface_was_brought_down = True
            else:
                logger.warning(f"Continuing to attempt MAC reversion for {interface} despite failure to bring it down first.")

            success, stdout_str, _ = self._run_command(['macchanger', '-p', interface])

            if success and stdout_str:
                restored_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if restored_mac and perm_mac and restored_mac.lower() == perm_mac.lower():
                    logger.info(f"Successfully reverted MAC for {interface} to permanent MAC: {restored_mac}. Previous MAC was: {current_mac_before_revert}")
                    log_event("mac_address_reverted", {"interface": interface, "reverted_from_mac": current_mac_before_revert, "reverted_to_mac": restored_mac, "permanent_mac": perm_mac})
                elif restored_mac:
                     logger.warning(f"MAC for {interface} reverted by 'macchanger -p' to {restored_mac}, but permanent MAC reported as {perm_mac}. Previous MAC: {current_mac_before_revert}")
                     log_event("mac_address_reverted_mismatch", {"interface": interface, "reverted_from_mac": current_mac_before_revert, "reverted_to_mac": restored_mac, "permanent_mac": perm_mac})
                else:
                    logger.warning(f"Could not parse reverted MAC from macchanger -p output for {interface}. Output: {stdout_str}")
                return restored_mac, perm_mac

            logger.error(f"Failed to revert MAC for {interface} to permanent hardware MAC. macchanger command stdout: {stdout_str}")
            return None, None
        finally:
            if interface_was_brought_down or not self._is_interface_up(interface):
                if not self._bring_interface_up(interface):
                    logger.error(f"CRITICAL: Interface {interface} was left down after revert_to_original_mac attempt.")
                else:
                    logger.info(f"Interface {interface} brought back up after revert_to_original_mac attempt.")
            elif self._is_interface_up(interface):
                 logger.debug(f"Interface {interface} is already up after revert_to_original_mac attempt.")
            else:
                 logger.warning(f"Interface {interface} is unexpectedly down after revert_to_original_mac and was not managed by this method.")

if __name__ == '__main__':
    # This is for basic testing of the MACChanger class itself.
    # Requires running as root and a valid interface (e.g., wlan0, eth0).
            new_mac, perm_mac = self._parse_macchanger_output(stdout_str)
            if new_mac:
                logger.info(f"Successfully set random MAC for {interface} to {new_mac} (Permanent: {perm_mac}). Original was: {original_mac}")
                log_event("mac_address_changed", {"interface": interface, "old_mac": original_mac, "new_mac": new_mac, "permanent_mac": perm_mac, "method": "random"})
            else: # macchanger command succeeded but output parsing failed
                logger.warning(f"Could not parse new MAC from macchanger -r output for {interface}. Output: {stdout_str}")
            return new_mac, perm_mac

        logger.error(f"Failed to set random MAC for {interface}. macchanger command stdout: {stdout_str}")
        return None, None

    def set_mac_specific(self, interface: str, new_mac_address: str) -> tuple[str | None, str | None]:
        logger.info(f"Attempting to set MAC for {interface} to {new_mac_address}.")
        if not interface_exists(interface): # Check added here for consistency, though get_current_mac would also check
            logger.error(f"Interface {interface} does not exist. Cannot set specific MAC.")
            return None, None
        original_mac = self.get_current_mac(interface)

        if not self._bring_interface_down(interface):
            logger.warning(f"Continuing to attempt MAC change for {interface} to {new_mac_address} despite failure to bring it down first.")

        success, stdout_str, _ = self._run_command(['macchanger', '-m', new_mac_address, interface])

        if not self._bring_interface_up(interface):
            logger.warning(f"Failed to bring interface {interface} up after attempting to set specific MAC.")

        if success and stdout_str:
            changed_mac, perm_mac = self._parse_macchanger_output(stdout_str)
            if changed_mac and changed_mac.lower() == new_mac_address.lower():
                logger.info(f"Successfully set MAC for {interface} to {changed_mac} (Permanent: {perm_mac}). Original was: {original_mac}")
                log_event("mac_address_changed", {"interface": interface, "old_mac": original_mac, "new_mac": changed_mac, "permanent_mac": perm_mac, "method": "specific"})
            elif changed_mac:
                logger.warning(f"MAC for {interface} changed to {changed_mac}, not the requested {new_mac_address}. Permanent: {perm_mac}. Original was: {original_mac}")
                log_event("mac_address_changed_unexpected", {"interface": interface, "old_mac": original_mac, "requested_mac": new_mac_address, "actual_new_mac": changed_mac, "permanent_mac": perm_mac, "method": "specific"})
            else: # macchanger command succeeded but output parsing failed
                logger.warning(f"Could not parse new MAC from macchanger -m output for {interface}. Output: {stdout_str}")
            return changed_mac, perm_mac

        logger.error(f"Failed to set MAC for {interface} to {new_mac_address}. macchanger command stdout: {stdout_str}")
        return None, None

    def revert_to_original_mac(self, interface: str) -> tuple[str | None, str | None]:
        logger.info(f"Attempting to revert MAC for {interface} to permanent hardware MAC.")
        if not interface_exists(interface): # Check added here
            logger.error(f"Interface {interface} does not exist. Cannot revert MAC.")
            return None, None
        current_mac_before_revert = self.get_current_mac(interface)

        if not self._bring_interface_down(interface):
            logger.warning(f"Continuing to attempt MAC reversion for {interface} despite failure to bring it down first.")

        success, stdout_str, _ = self._run_command(['macchanger', '-p', interface])

        if not self._bring_interface_up(interface):
            logger.warning(f"Failed to bring interface {interface} up after attempting to revert MAC.")

        if success and stdout_str:
            restored_mac, perm_mac = self._parse_macchanger_output(stdout_str)
            if restored_mac and perm_mac and restored_mac.lower() == perm_mac.lower():
                logger.info(f"Successfully reverted MAC for {interface} to permanent MAC: {restored_mac}. Previous MAC was: {current_mac_before_revert}")
                log_event("mac_address_reverted", {"interface": interface, "reverted_from_mac": current_mac_before_revert, "reverted_to_mac": restored_mac, "permanent_mac": perm_mac})
            elif restored_mac:
                 logger.warning(f"MAC for {interface} reverted by 'macchanger -p' to {restored_mac}, but permanent MAC reported as {perm_mac}. Previous MAC: {current_mac_before_revert}")
                 log_event("mac_address_reverted_mismatch", {"interface": interface, "reverted_from_mac": current_mac_before_revert, "reverted_to_mac": restored_mac, "permanent_mac": perm_mac})
            else:
                logger.warning(f"Could not parse reverted MAC from macchanger -p output for {interface}. Output: {stdout_str}")
            return restored_mac, perm_mac

        logger.error(f"Failed to revert MAC for {interface} to permanent hardware MAC. macchanger command stdout: {stdout_str}")
        return None, None

if __name__ == '__main__':
    # This is for basic testing of the MACChanger class itself.
    # Requires running as root and a valid interface (e.g., wlan0, eth0).
    # Replace 'your_interface' with an actual interface.
    # Ensure 'macchanger' and 'ip' commands are available.

    # Setup basic logging for the test
    test_logger = logging.getLogger()
    test_logger.setLevel(logging.DEBUG) # Show all logs for testing
    test_handler = logging.StreamHandler()
    test_formatter = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
    test_handler.setFormatter(test_formatter)
    test_logger.addHandler(test_handler)

    iface_to_test = "eth0" # CHANGE THIS to a real, non-critical interface for testing
                           # Using a virtual interface or a test VM's interface is safer.

    # --- WARNING ---
    # The following tests will change the MAC address of the specified interface.
    # Do NOT run on a critical production interface without understanding the consequences.
    # It's best to run this on a test machine or a non-essential interface.
    # --- WARNING ---

    changer = MACChanger()
    if not changer._check_macchanger_installed():
        logger.error("macchanger is not installed. Aborting tests.")
        exit(1)

    logger.info(f"--- Testing MACChanger on interface: {iface_to_test} ---")

    original_mac = changer.get_current_mac(iface_to_test)
    logger.info(f"Initial current MAC: {original_mac}")
    if not original_mac:
        logger.error(f"Could not retrieve initial MAC for {iface_to_test}. Further tests might be unreliable.")
        # exit(1) # Decide if to stop or continue

    logger.info("--- Test 1: Set Random MAC ---")
    new_random_mac, perm_mac_after_random = changer.set_mac_random(iface_to_test)
    logger.info(f"Set to Random MAC: {new_random_mac}, Permanent MAC: {perm_mac_after_random}")
    current_mac_after_random = changer.get_current_mac(iface_to_test)
    logger.info(f"Current MAC after random set: {current_mac_after_random}")
    assert new_random_mac == current_mac_after_random, "New random MAC does not match current MAC!"

    # Only proceed if original_mac was fetched, otherwise we can't revert properly.
    if original_mac:
        logger.info("--- Test 2: Revert to Original MAC ---")
        reverted_mac, perm_mac_after_revert = changer.revert_to_original_mac(iface_to_test)
        logger.info(f"Reverted to Original MAC: {reverted_mac}, Permanent MAC: {perm_mac_after_revert}")
        current_mac_after_revert = changer.get_current_mac(iface_to_test)
        logger.info(f"Current MAC after revert: {current_mac_after_revert}")
        # Depending on macchanger's behavior and system, reverted_mac might be the permanent one.
        # The key is that current_mac_after_revert should be the permanent MAC.
        assert perm_mac_after_revert == current_mac_after_revert, "Reverted MAC does not match permanent MAC!"
        # If original_mac was the permanent MAC, then this should also hold:
        # assert original_mac == current_mac_after_revert, "Reverted MAC does not match initial original MAC!"
        # However, if original_mac was already a spoofed one, this assertion would be false.
        # The most reliable check is if current MAC == permanent MAC after -p.

    logger.info("--- Test 3: Set Specific MAC ---")
    specific_test_mac = "aa:bb:cc:dd:ee:ff"
    logger.info(f"Attempting to set MAC to specific: {specific_test_mac}")
    new_specific_mac, perm_mac_after_specific = changer.set_mac_specific(iface_to_test, specific_test_mac)
    logger.info(f"Set to Specific MAC: {new_specific_mac}, Permanent MAC: {perm_mac_after_specific}")
    current_mac_after_specific = changer.get_current_mac(iface_to_test)
    logger.info(f"Current MAC after specific set: {current_mac_after_specific}")
    assert new_specific_mac.lower() == specific_test_mac.lower(), "New specific MAC does not match requested specific MAC!"
    assert current_mac_after_specific.lower() == specific_test_mac.lower(), "Current MAC does not match requested specific MAC!"

    # Final revert to permanent MAC if possible
    if perm_mac_after_specific: # If we know the permanent MAC
        logger.info(f"--- Final Revert to Permanent MAC: {perm_mac_after_specific} ---")
        changer.revert_to_original_mac(iface_to_test)
        final_mac = changer.get_current_mac(iface_to_test)
        logger.info(f"Final current MAC: {final_mac}. Should be permanent.")
        assert final_mac == perm_mac_after_specific, "Final MAC is not the permanent MAC!"

    logger.info("--- MACChanger Tests Completed ---")
