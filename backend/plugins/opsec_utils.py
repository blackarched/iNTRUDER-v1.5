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
        if not self.is_macchanger_available():
            logger.error("macchanger command not found. MACChanger utility will not function.")
            # You could raise an exception here or let it fail when methods are called.
            # For now, logging an error. Methods will likely fail with FileNotFoundError.
            # raise RuntimeError("macchanger command not found.")
            pass


    def is_macchanger_available(self) -> bool:
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
        if success or "Permanent MAC" in stdout_str: # Check for "Permanent MAC" in output as macchanger -s might return 0 even if it couldn't read current
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
            # Always try to bring the interface up if we attempted to bring it down, or if it's unexpectedly down.
            if interface_was_brought_down or not self._is_interface_up(interface):
                if not self._bring_interface_up(interface):
                    logger.error(f"CRITICAL: Interface {interface} was left down after set_mac_random attempt.")
                else:
                    logger.info(f"Interface {interface} brought back up after set_mac_random attempt.")


    def _is_interface_up(self, interface: str) -> bool:
        """Helper to check if interface is operationally up."""
        if not interface_exists(interface): return False
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True, check=True)
            return "state UP" in result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug(f"Could not determine if interface {interface} is up: {e}")
            return False


    def set_mac_specific(self, interface: str, new_mac_address: str) -> tuple[str | None, str | None]:
        logger.info(f"Attempting to set MAC for {interface} to {new_mac_address}.")
        if not interface_exists(interface):
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
                elif changed_mac: # MAC changed, but not to what we asked.
                    logger.warning(f"MAC for {interface} changed to {changed_mac}, not the requested {new_mac_address}. Permanent: {perm_mac}. Original was: {original_mac}")
                    log_event("mac_address_changed_unexpected", {"interface": interface, "old_mac": original_mac, "requested_mac": new_mac_address, "actual_new_mac": changed_mac, "permanent_mac": perm_mac, "method": "specific"})
                else: # macchanger command succeeded but output parsing failed
                    logger.warning(f"Could not parse new MAC from macchanger -m output for {interface}. Output: {stdout_str}")
                return changed_mac, perm_mac

            logger.error(f"Failed to set MAC for {interface} to {new_mac_address}. macchanger command stdout: {stdout_str}")
            return None, None
        finally:
            if interface_was_brought_down or not self._is_interface_up(interface):
                if not self._bring_interface_up(interface):
                    logger.error(f"CRITICAL: Interface {interface} was left down after set_mac_specific attempt.")
                else:
                    logger.info(f"Interface {interface} brought back up after set_mac_specific attempt.")


    def revert_to_original_mac(self, interface: str) -> tuple[str | None, str | None]:
        logger.info(f"Attempting to revert MAC for {interface} to permanent hardware MAC.")
        if not interface_exists(interface):
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
                elif restored_mac: # Reverted, but maybe not to permanent (e.g. if permanent MAC is weird or parsing of perm_mac failed)
                     logger.warning(f"MAC for {interface} reverted by 'macchanger -p' to {restored_mac}, but permanent MAC reported as {perm_mac}. Previous MAC: {current_mac_before_revert}")
                     log_event("mac_address_reverted_mismatch", {"interface": interface, "reverted_from_mac": current_mac_before_revert, "reverted_to_mac": restored_mac, "permanent_mac": perm_mac})
                else: # macchanger command succeeded but output parsing failed
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

if __name__ == '__main__':
    # This is for basic testing of the MACChanger class itself.
    # Requires running as root and a valid interface (e.g., wlan0, eth0).
    # Replace 'your_interface' with an actual interface.
    # Ensure 'macchanger' and 'ip' commands are available.

    # Setup basic logging for the test
    test_logger = logging.getLogger() # Get root logger
    # Ensure it's clear of other handlers if this is meant to be standalone test
    for handler in test_logger.handlers[:]:
        test_logger.removeHandler(handler)

    test_logger.setLevel(logging.DEBUG) # Show all logs for testing
    test_handler = logging.StreamHandler()
    test_formatter = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
    test_handler.setFormatter(test_formatter)
    test_logger.addHandler(test_handler)

    # Configure this specific module's logger level too, if it was set higher by default from other imports
    logging.getLogger(__name__).setLevel(logging.DEBUG)


    iface_to_test = "eth0" # CHANGE THIS to a real, non-critical interface for testing
                           # Using a virtual interface or a test VM's interface is safer.
                           # Example: for a virtual interface 'veth_test_mac'
                           # Ensure it's up: sudo ip link add veth_test_mac type veth peer name veth_test_peer && sudo ip link set veth_test_mac up

    # --- WARNING ---
    # The following tests will change the MAC address of the specified interface.
    # Do NOT run on a critical production interface without understanding the consequences.
    # It's best to run this on a test machine or a non-essential interface.
    # --- WARNING ---

    changer = MACChanger()
    if not changer.is_macchanger_available():
        logger.error("macchanger is not installed. Aborting tests.")
        exit(1)

    if not interface_exists(iface_to_test):
        logger.error(f"Test interface {iface_to_test} does not exist. Aborting tests.")
        logger.error("If using a virtual interface like veth, create and bring it up first.")
        logger.error("Example: sudo ip link add veth_test_mac type veth peer name veth_test_peer && sudo ip link set veth_test_mac up")
        exit(1)


    logger.info(f"--- Testing MACChanger on interface: {iface_to_test} ---")

    original_mac = changer.get_current_mac(iface_to_test)
    logger.info(f"Initial current MAC for {iface_to_test}: {original_mac}")

    permanent_mac_initial_report = None
    # Get permanent MAC directly for reference if possible (macchanger -s output)
    _, stdout_s, _ = changer._run_command(['macchanger', '-s', iface_to_test], check_errors=False)
    _, perm_mac_from_s = changer._parse_macchanger_output(stdout_s)
    if perm_mac_from_s:
        permanent_mac_initial_report = perm_mac_from_s
        logger.info(f"Permanent MAC for {iface_to_test} (from -s): {permanent_mac_initial_report}")
    else:
        logger.warning(f"Could not determine permanent MAC for {iface_to_test} from 'macchanger -s' output.")


    if not original_mac:
        logger.warning(f"Could not retrieve initial MAC for {iface_to_test}. Some tests might be less effective.")

    logger.info("--- Test 1: Set Random MAC ---")
    new_random_mac, perm_mac_after_random = changer.set_mac_random(iface_to_test)
    logger.info(f"Set to Random MAC result: {new_random_mac}, Reported Permanent MAC: {perm_mac_after_random}")
    current_mac_after_random = changer.get_current_mac(iface_to_test)
    logger.info(f"Current MAC after random set: {current_mac_after_random}")

    if new_random_mac and current_mac_after_random:
        assert new_random_mac.lower() == current_mac_after_random.lower(), "New random MAC does not match current MAC!"
    elif new_random_mac and not current_mac_after_random:
        logger.warning("Random MAC was set, but get_current_mac failed afterwards.")
    elif not new_random_mac:
        logger.warning("Failed to set or parse random MAC.")


    # Revert to permanent before specific test, using the permanent MAC reported by the random change
    # This makes tests more independent.
    if perm_mac_after_random:
        logger.info(f"--- Intermediate Revert to Permanent MAC: {perm_mac_after_random} ---")
        changer.revert_to_original_mac(iface_to_test) # This should set it to perm_mac_after_random
        current_mac_after_intermediate_revert = changer.get_current_mac(iface_to_test)
        logger.info(f"Current MAC after intermediate revert: {current_mac_after_intermediate_revert}")
        if current_mac_after_intermediate_revert:
             assert current_mac_after_intermediate_revert.lower() == perm_mac_after_random.lower(), "Intermediate revert did not match reported permanent MAC."
        else:
            logger.warning("Failed to get MAC after intermediate revert.")


    logger.info("--- Test 2: Set Specific MAC ---")
    specific_test_mac = "aa:bb:cc:dd:ee:ff"
    # Ensure specific_test_mac is different from current permanent MAC for a valid test
    if perm_mac_after_random and specific_test_mac.lower() == perm_mac_after_random.lower():
        specific_test_mac = "00:11:22:33:44:55" # Choose a different one
        logger.info(f"Original specific_test_mac was same as permanent, changed to: {specific_test_mac}")

    logger.info(f"Attempting to set MAC to specific: {specific_test_mac}")
    new_specific_mac, perm_mac_after_specific = changer.set_mac_specific(iface_to_test, specific_test_mac)
    logger.info(f"Set to Specific MAC result: {new_specific_mac}, Reported Permanent MAC: {perm_mac_after_specific}")
    current_mac_after_specific = changer.get_current_mac(iface_to_test)
    logger.info(f"Current MAC after specific set: {current_mac_after_specific}")

    if new_specific_mac and current_mac_after_specific:
        assert new_specific_mac.lower() == specific_test_mac.lower(), "New specific MAC does not match requested specific MAC!"
        assert current_mac_after_specific.lower() == specific_test_mac.lower(), "Current MAC does not match requested specific MAC!"
    elif new_specific_mac and not current_mac_after_specific:
         logger.warning("Specific MAC was set, but get_current_mac failed afterwards.")
    elif not new_specific_mac:
        logger.warning("Failed to set or parse specific MAC.")

    # Final revert to permanent MAC
    # Use the permanent MAC reported by the LAST successful operation (set_mac_specific) if available
    # Otherwise, fallback to the one reported by set_mac_random, or the initial 'macchanger -s'
    final_perm_mac_target = perm_mac_after_specific or perm_mac_after_random or permanent_mac_initial_report
    if final_perm_mac_target:
        logger.info(f"--- Final Revert to Target Permanent MAC: {final_perm_mac_target} ---")
        reverted_mac, perm_mac_final_revert = changer.revert_to_original_mac(iface_to_test)
        logger.info(f"Reverted MAC reported by command: {reverted_mac}, Permanent MAC from command: {perm_mac_final_revert}")
        final_mac_check = changer.get_current_mac(iface_to_test)
        logger.info(f"Final current MAC after revert: {final_mac_check}")
        if final_mac_check and perm_mac_final_revert: # Both should be available
            assert final_mac_check.lower() == perm_mac_final_revert.lower(), "Final MAC is not the permanent MAC reported by the revert command!"
            assert final_mac_check.lower() == final_perm_mac_target.lower(), "Final MAC is not the target permanent MAC!"
        elif not final_mac_check:
            logger.error("Failed to get final MAC address after attempting revert.")
        else:
            logger.warning("Could not fully verify final MAC state due to missing report values.")
    else:
        logger.warning("No reliable permanent MAC was determined throughout tests to perform a final revert check.")

    logger.info("--- MACChanger Tests Completed ---")
