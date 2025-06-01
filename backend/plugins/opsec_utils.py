import logging
import subprocess
import re
import os # Added for os.path.join
# Adjust the import based on the final location of config if this were a real multi-level package.
# For the current flat backend structure where server.py imports backend.config,
# and opsec_utils.py is in backend.plugins, this needs to be:
from .. import config # Assuming this correctly imports the backend.config module
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

        # Prepend sudo to all commands run through this method if they are not already prefixed.
        # This is a general approach; specific command constructions below will ensure sudo is used.
        effective_command_args = command_args
        if command_args[0] != 'sudo':
            # This logic might be too broad if some commands should not use sudo.
            # For MACChanger, most operations require privileges.
            # We will ensure specific command constructions use sudo.
            # logger.warning(f"Command '{command_args[0]}' was not prefixed with sudo. This might change.")
            pass # Let specific command constructions handle sudo.

        try:
            logger.info(f"Executing command via _run_command: {' '.join(effective_command_args)}")
            process = subprocess.run(effective_command_args, capture_output=True, text=True, check=check_errors, timeout=timeout)
            stdout_str = process.stdout.strip() if process.stdout else ""
            stderr_str = process.stderr.strip() if process.stderr else ""

            if process.returncode == 0:
                success = True
                if stdout_str: logger.debug(f"Command stdout: {stdout_str}")
                if stderr_str: logger.debug(f"Command stderr (often informational): {stderr_str}")
            else:
                logger.warning(f"Command '{' '.join(effective_command_args)}' exited with code {process.returncode}.")
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
            cmd_name = effective_command_args[0]
            if cmd_name == 'sudo': # If sudo itself is not found or script path is wrong
                cmd_name = effective_command_args[1] if len(effective_command_args) > 1 else cmd_name
            logger.error(f"Command or script '{cmd_name}' not found. Is it installed and in PATH, or is the script path correct?", exc_info=True)
            stderr_str = f"Command or script '{cmd_name}' not found."
        except Exception as e:
            logger.error(f"An unexpected error occurred running command '{' '.join(effective_command_args)}'", exc_info=True)
            stderr_str = str(e)

        return success, stdout_str, stderr_str

    def _bring_interface_down(self, interface: str) -> bool:
        logger.info(f"Bringing interface {interface} down using sudo and wrapper script.")
        script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'set_if_state.sh')
        cmd = [config.SUDO_COMMAND, script_path, interface, 'down']
        success, _, _ = self._run_command(cmd)
        return success

    def _bring_interface_up(self, interface: str) -> bool:
        logger.info(f"Bringing interface {interface} up using sudo and wrapper script.")
        script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'set_if_state.sh')
        cmd = [config.SUDO_COMMAND, script_path, interface, 'up']
        success, _, _ = self._run_command(cmd)
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
        logger.info(f"Getting current MAC for {interface} using sudo and wrapper script.")
        script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'macchanger_show.sh')
        cmd = [config.SUDO_COMMAND, script_path, interface]
        success, stdout_str, _ = self._run_command(cmd, check_errors=False)

        # If macchanger_show.sh directly outputs macchanger -s results, parsing should be similar.
        # Success of the script is primary; "Permanent MAC" might not be in direct output if script filters.
        if success and stdout_str: # Rely on script success and non-empty output
            current, _ = self._parse_macchanger_output(stdout_str)
            if current:
                return current
            else: # Script succeeded but output parsing failed.
                logger.warning(f"macchanger_show.sh for {interface} succeeded, but output parsing failed. stdout: {stdout_str}")
                return None # Or perhaps return stdout_str if it's expected to be just the MAC

        logger.warning(f"Failed to get current MAC for {interface} using script. stdout: {stdout_str}")
        return None

    def set_mac_random(self, interface: str) -> tuple[str | None, str | None]:
        if not interface_exists(interface):
            logger.error(f"Interface {interface} does not exist. Cannot set random MAC.")
            return None, None
        logger.info(f"Attempting to set random MAC for {interface} using sudo and wrapper script.")
        original_mac = self.get_current_mac(interface)
        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface): # Uses wrapper
                interface_was_brought_down = True
            else:
                logger.warning(f"Continuing to attempt MAC change for {interface} (random) despite failure to bring it down first.")

            script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'macchanger_set_random.sh')
            cmd = [config.SUDO_COMMAND, script_path, interface]
            success, stdout_str, _ = self._run_command(cmd)

            if success and stdout_str:
                new_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if new_mac:
                    logger.info(f"Successfully set random MAC for {interface} to {new_mac} (Permanent: {perm_mac}). Original was: {original_mac}")
                    log_event("mac_address_changed", {"interface": interface, "old_mac": original_mac, "new_mac": new_mac, "permanent_mac": perm_mac, "method": "random_script"})
                else:
                    logger.warning(f"macchanger_set_random.sh for {interface} succeeded, but output parsing failed. Output: {stdout_str}")
                return new_mac, perm_mac

            logger.error(f"Failed to set random MAC for {interface} using script. macchanger_set_random.sh stdout: {stdout_str}")
            return None, None
        finally:
            # Ensure interface is brought up if it was taken down or is unexpectedly down
            if interface_was_brought_down or not self._is_interface_up(interface): # _is_interface_up also uses wrapper
                if not self._bring_interface_up(interface): # Uses wrapper
                    logger.error(f"CRITICAL: Interface {interface} was left down after set_mac_random (script) attempt.")
                else:
                    logger.info(f"Interface {interface} brought back up after set_mac_random (script) attempt.")
            elif self._is_interface_up(interface):
                 logger.debug(f"Interface {interface} is already up after set_mac_random (script) attempt.")
            else:
                 logger.warning(f"Interface {interface} is unexpectedly down after set_mac_random (script) and was not managed by this method.")

    def _is_interface_up(self, interface: str) -> bool:
        """Helper to check if interface is operationally up using a wrapper script."""
        if not interface_exists(interface): return False
        logger.debug(f"Checking UP state for {interface} using sudo and wrapper script.")
        # This script would need to parse 'ip link show <interface>' output for 'state UP'
        script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'get_if_state.sh')
        cmd = [config.SUDO_COMMAND, script_path, interface]
        success, stdout_str, _ = self._run_command(cmd) # stdout_str expected to be "UP" or "DOWN" or "UNKNOWN"
        if success and stdout_str.upper() == "UP":
            logger.debug(f"Interface {interface} reported as UP by script.")
            return True
        logger.debug(f"Interface {interface} reported as not UP by script (or script failed). State: '{stdout_str}'")
        return False

    def set_mac_specific(self, interface: str, new_mac_address: str) -> tuple[str | None, str | None]:
        logger.info(f"Attempting to set MAC for {interface} to {new_mac_address} using sudo and wrapper script.")
        if not interface_exists(interface):
            logger.error(f"Interface {interface} does not exist. Cannot set specific MAC.")
            return None, None
        original_mac = self.get_current_mac(interface)
        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface): # Uses wrapper
                interface_was_brought_down = True
            else:
                logger.warning(f"Continuing to attempt MAC change for {interface} to {new_mac_address} despite failure to bring it down first.")

            script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'macchanger_set_specific.sh')
            cmd = [config.SUDO_COMMAND, script_path, new_mac_address, interface]
            success, stdout_str, _ = self._run_command(cmd)

            if success and stdout_str:
                changed_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if changed_mac and changed_mac.lower() == new_mac_address.lower():
                    logger.info(f"Successfully set MAC for {interface} to {changed_mac} (Permanent: {perm_mac}). Original was: {original_mac}")
                    log_event("mac_address_changed", {"interface": interface, "old_mac": original_mac, "new_mac": changed_mac, "permanent_mac": perm_mac, "method": "specific_script"})
                elif changed_mac:
                    logger.warning(f"MAC for {interface} changed to {changed_mac} via script, not the requested {new_mac_address}. Permanent: {perm_mac}. Original was: {original_mac}")
                    log_event("mac_address_changed_unexpected", {"interface": interface, "old_mac": original_mac, "requested_mac": new_mac_address, "actual_new_mac": changed_mac, "permanent_mac": perm_mac, "method": "specific_script"})
                else:
                    logger.warning(f"macchanger_set_specific.sh for {interface} succeeded, but output parsing failed. Output: {stdout_str}")
                return changed_mac, perm_mac

            logger.error(f"Failed to set MAC for {interface} to {new_mac_address} using script. macchanger_set_specific.sh stdout: {stdout_str}")
            return None, None
        finally:
            if interface_was_brought_down or not self._is_interface_up(interface): # Uses wrapper
                if not self._bring_interface_up(interface): # Uses wrapper
                    logger.error(f"CRITICAL: Interface {interface} was left down after set_mac_specific (script) attempt.")
                else:
                    logger.info(f"Interface {interface} brought back up after set_mac_specific (script) attempt.")
            elif self._is_interface_up(interface):
                 logger.debug(f"Interface {interface} is already up after set_mac_specific (script) attempt.")
            else:
                 logger.warning(f"Interface {interface} is unexpectedly down after set_mac_specific (script) and was not managed by this method.")

    def revert_to_original_mac(self, interface: str) -> tuple[str | None, str | None]:
        logger.info(f"Attempting to revert MAC for {interface} to permanent hardware MAC using sudo and wrapper script.")
        if not interface_exists(interface):
            logger.error(f"Interface {interface} does not exist. Cannot revert MAC.")
            return None, None
        current_mac_before_revert = self.get_current_mac(interface)
        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface): # Uses wrapper
                interface_was_brought_down = True
            else:
                logger.warning(f"Continuing to attempt MAC reversion for {interface} despite failure to bring it down first.")

            script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'macchanger_revert_perm.sh')
            cmd = [config.SUDO_COMMAND, script_path, interface]
            success, stdout_str, _ = self._run_command(cmd)

            if success and stdout_str:
                restored_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if restored_mac and perm_mac and restored_mac.lower() == perm_mac.lower():
                    logger.info(f"Successfully reverted MAC for {interface} to permanent MAC: {restored_mac} via script. Previous MAC was: {current_mac_before_revert}")
                    log_event("mac_address_reverted", {"interface": interface, "reverted_from_mac": current_mac_before_revert, "reverted_to_mac": restored_mac, "permanent_mac": perm_mac, "method": "revert_script"})
                elif restored_mac:
                     logger.warning(f"MAC for {interface} reverted by script to {restored_mac}, but permanent MAC reported as {perm_mac}. Previous MAC: {current_mac_before_revert}")
                     log_event("mac_address_reverted_mismatch", {"interface": interface, "reverted_from_mac": current_mac_before_revert, "reverted_to_mac": restored_mac, "permanent_mac": perm_mac, "method": "revert_script"})
                else:
                    logger.warning(f"macchanger_revert_perm.sh for {interface} succeeded, but output parsing failed. Output: {stdout_str}")
                return restored_mac, perm_mac

            logger.error(f"Failed to revert MAC for {interface} to permanent hardware MAC using script. macchanger_revert_perm.sh stdout: {stdout_str}")
            return None, None
        finally:
            if interface_was_brought_down or not self._is_interface_up(interface): # Uses wrapper
                if not self._bring_interface_up(interface): # Uses wrapper
                    logger.error(f"CRITICAL: Interface {interface} was left down after revert_to_original_mac (script) attempt.")
                else:
                    logger.info(f"Interface {interface} brought back up after revert_to_original_mac (script) attempt.")
            elif self._is_interface_up(interface):
                 logger.debug(f"Interface {interface} is already up after revert_to_original_mac (script) attempt.")
            else:
                 logger.warning(f"Interface {interface} is unexpectedly down after revert_to_original_mac (script) and was not managed by this method.")

if __name__ == '__main__':
    # This is for basic testing of the MACChanger class itself.
    # Requires running as root and a valid interface (e.g., wlan0, eth0).
    # The wrapper scripts (/opt/intruder/scripts/*) would need to exist and be correctly configured in sudoers.
    # Since we are not creating the scripts in this task, this test block will not fully function as intended.
    # It's here for conceptual understanding of how it would be tested.

    # Duplicated code from lines 216-283 has been removed from here to avoid confusion.
    # The original test code structure is preserved below.
    # Setup basic logging for the test
    test_logger = logging.getLogger()
    test_logger.setLevel(logging.DEBUG) # Show all logs for testing
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
