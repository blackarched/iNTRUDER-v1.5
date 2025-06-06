"""
Operational Security (OpSec) utilities, currently featuring MACChanger.
Provides functionalities to manage and spoof MAC addresses using the 'macchanger' tool.
"""
import logging
import subprocess
import re
import sys # For __main__ test block
from typing import Tuple, Optional, List, Dict, Any

# Adjust the import based on the final location of config if this were a real multi-level package.
# For the current flat backend structure where server.py imports backend.config,
# and opsec_utils.py is in backend.plugins, this needs to be:
try:
    from .. import config
    from ..core.event_logger import log_event
    from ..core.network_utils import interface_exists
except ImportError:
    # Fallback for direct execution or different environment setups
    logger_fallback = logging.getLogger(__name__) # Use a temporary logger for this message
    logger_fallback.warning("Running MACChanger with fallback imports. Ensure necessary modules (config, core.event_logger, core.network_utils) are accessible.")
    # Define dummy config and log_event if they are not available for standalone testing
    class DummyConfigFallback: # Renamed to avoid conflict if config is later imported
        MAC_CHANGE_ENABLED = False # Default secure behavior
    config = DummyConfigFallback() # type: ignore

    def log_event(event_type: str, data: Dict[str, Any]) -> None: # type: ignore
        print(f"DUMMY_LOG_EVENT: {event_type} - {data}")

    def interface_exists(iface_name: str) -> bool: # type: ignore
        # Basic fallback for interface_exists if core.network_utils is not available
        try:
            subprocess.run(['ip', 'link', 'show', iface_name], check=True, capture_output=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False


logger: logging.Logger = logging.getLogger(__name__)

class MACChanger:
    """
    A utility class to manage MAC address changes for a network interface using 'macchanger'.
    It allows getting the current MAC, setting a random MAC, setting a specific MAC,
    and reverting to the permanent hardware MAC address.
    Operations typically require root privileges.
    """
    def __init__(self) -> None:
        """
        Initializes the MACChanger.
        Checks if 'macchanger' command is available upon instantiation.
        """
        self.macchanger_path: Optional[str] = self._find_macchanger_path()
        if not self.macchanger_path:
            # Enhanced logging message
            logger.error(
                "CRITICAL: 'macchanger' command not found or not executable. "
                "MACChanger utility will be non-functional. "
                "Please install macchanger (e.g., 'sudo apt-get install macchanger') "
                "and ensure it's in the system PATH."
            )
            # No exception raised here to allow conditional use, but methods will fail.
            # Callers should ideally check functionality or handle failures from methods.
        else:
            logger.debug(f"MACChanger initialized. Found 'macchanger' at: {self.macchanger_path}")


    def _find_macchanger_path(self) -> Optional[str]:
        """Checks if macchanger is installed and returns its path."""
        try:
            # `subprocess.check_output` is simpler for just getting command path via `which`
            # Using `which` is more direct for finding the path.
            path_bytes = subprocess.check_output(['which', 'macchanger'], timeout=5)
            path_str = path_bytes.decode('utf-8').strip()
            if path_str:
                # Verify it's executable, though `which` usually implies this.
                process_version = subprocess.run([path_str, '--version'], capture_output=True, text=True, check=True, timeout=5)
                logger.info(f"macchanger detected at '{path_str}': {process_version.stdout.strip()}")
                return path_str
            return None
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug(f"Failed to find or verify 'macchanger': {e}")
            return None

    def _run_command(self, command_args: List[str], check_errors: bool = True, timeout: int = 10) -> Tuple[bool, str, str]:
        """
        Helper method to run subprocess commands, prepending macchanger_path.

        Args:
            command_args: List of command arguments, starting with the macchanger option (e.g., ['-s', interface]).
            check_errors: If True, raises CalledProcessError for non-zero exit codes.
            timeout: Timeout in seconds for the command.

        Returns:
            Tuple (success: bool, stdout_str: str, stderr_str: str)
        """
        if not self.macchanger_path:
            logger.error("macchanger path not found, cannot execute command.")
            return False, "", "macchanger command not found during _run_command"

        full_command = [self.macchanger_path] + command_args
        success = False
        stdout_str = ""
        stderr_str = ""
        try:
            logger.info(f"Executing command: {' '.join(full_command)}")
            process = subprocess.run(full_command, capture_output=True, text=True, check=check_errors, timeout=timeout, encoding='utf-8', errors='ignore')
            stdout_str = process.stdout.strip() if process.stdout else ""
            stderr_str = process.stderr.strip() if process.stderr else ""

            if process.returncode == 0:
                success = True
                if stdout_str: logger.debug(f"Command stdout: {stdout_str}")
                if stderr_str: logger.debug(f"Command stderr (often informational): {stderr_str}")
            else: # Should only be reached if check_errors=False and it's a non-zero exit
                logger.warning(f"Command '{' '.join(full_command)}' exited with code {process.returncode}.")
                if stdout_str: logger.warning(f"Stdout: {stdout_str}")
                if stderr_str: logger.warning(f"Stderr: {stderr_str}")
        # Errors are now more specific based on what subprocess.run can raise.
        except subprocess.CalledProcessError as e:
            stdout_str = e.stdout.strip() if e.stdout else ""
            stderr_str = e.stderr.strip() if e.stderr else ""
            logger.error(f"Command '{' '.join(e.cmd)}' failed with code {e.returncode}. Stdout: '{stdout_str}', Stderr: '{stderr_str}'", exc_info=True)
        except subprocess.TimeoutExpired as e:
            stdout_str = e.stdout.strip() if e.stdout.strip() else "" if isinstance(e.stdout, str) else (e.stdout.decode('utf-8','ignore').strip() if e.stdout else "")
            stderr_str = e.stderr.strip() if e.stderr.strip() else "" if isinstance(e.stderr, str) else (e.stderr.decode('utf-8','ignore').strip() if e.stderr else "")
            logger.error(f"Command '{' '.join(e.cmd)}' timed out after {timeout}s. Partial stdout: '{stdout_str}', Partial stderr: '{stderr_str}'", exc_info=True)
        except FileNotFoundError: # Should not happen if self.macchanger_path is set, but good for safety.
            logger.error(f"Command '{full_command[0]}' not found. This indicates an issue with macchanger_path.", exc_info=True)
            stderr_str = f"Command '{full_command[0]}' not found."
        except Exception as e:
            logger.error(f"An unexpected error occurred running command '{' '.join(full_command)}': {e}", exc_info=True)
            stderr_str = str(e)
        return success, stdout_str, stderr_str

    def _bring_interface_down(self, interface: str) -> bool:
        """Brings the specified network interface down using 'ip link set dev <interface> down'."""
        logger.info(f"Bringing interface '{interface}' down.")
        # Using system 'ip' command, not macchanger for this.
        success, _, stderr = self._run_command_system(['ip', 'link', 'set', 'dev', interface, 'down'])
        if not success:
            logger.error(f"Failed to bring interface '{interface}' down. Stderr: {stderr}")
        return success

    def _bring_interface_up(self, interface: str) -> bool:
        """Brings the specified network interface up using 'ip link set dev <interface> up'."""
        logger.info(f"Bringing interface '{interface}' up.")
        success, _, stderr = self._run_command_system(['ip', 'link', 'set', 'dev', interface, 'up'])
        if not success:
            logger.error(f"Failed to bring interface '{interface}' up. Stderr: {stderr}")
        return success

    def _run_command_system(self, command_args: List[str], check_errors: bool = True, timeout: int = 10) -> Tuple[bool, str, str]:
        """ Helper for system commands like 'ip' """
        # This is a simplified version of _run_command for non-macchanger system utilities.
        # It does not use self.macchanger_path.
        success = False; stdout_str = ""; stderr_str = ""
        try: # Corrected Python try block
            logger.debug(f"Executing system command: {{' '.join(command_args)}}")
            process = subprocess.run(command_args, capture_output=True, text=True, check=check_errors, timeout=timeout, encoding='utf-8', errors='ignore')
            stdout_str = process.stdout.strip() if process.stdout else ""
            stderr_str = process.stderr.strip() if process.stderr else ""
            if process.returncode == 0:
                success = True
        except subprocess.CalledProcessError as e:
            logger.error(f"System command {{' '.join(command_args)}} failed with RC {e.returncode}: {e.stderr}", exc_info=True)
            stderr_str = e.stderr.strip() if e.stderr else str(e) # Ensure stderr is string
            stdout_str = e.stdout.strip() if e.stdout else ""
        except subprocess.TimeoutExpired as e:
            logger.error(f"System command {{' '.join(command_args)}} timed out: {e}", exc_info=True)
            stderr_str = e.stderr.decode('utf-8', 'ignore').strip() if e.stderr else str(e)
            stdout_str = e.stdout.decode('utf-8', 'ignore').strip() if e.stdout else ""
        except FileNotFoundError as e:
            logger.error(f"System command not found: {command_args[0]} ({e})", exc_info=True)
            stderr_str = f"Command not found: {command_args[0]}"
        except Exception as e: # General exception
            logger.error(f"System command {{' '.join(command_args)}} failed unexpectedly: {e}", exc_info=True)
            stderr_str = str(e)
        return success, stdout_str, stderr_str


    def _parse_macchanger_output(self, output: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parses macchanger output to extract current/new and permanent MAC addresses.

        Args:
            output: The stdout string from a macchanger command.

        Returns:
            A tuple (current_or_new_mac, permanent_mac).
            'current_or_new_mac' will be the "New MAC" if present, otherwise "Current MAC".
            Returns (None, None) if parsing fails.
        """
        current_mac, permanent_mac, new_mac = None, None, None
        # Regex to capture MAC addresses. Handles mixed case.
        mac_regex = r"([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})"

        current_match = re.search(fr"Current MAC:\s*({mac_regex})", output, re.IGNORECASE)
        if current_match:
            current_mac = current_match.group(1)
            logger.debug(f"Parsed Current MAC: {current_mac}")

        permanent_match = re.search(fr"Permanent MAC:\s*({mac_regex})", output, re.IGNORECASE)
        if permanent_match:
            permanent_mac = permanent_match.group(1)
            logger.debug(f"Parsed Permanent MAC: {permanent_mac}")

        new_match = re.search(fr"New MAC:\s*({mac_regex})", output, re.IGNORECASE)
        if new_match:
            new_mac = new_match.group(1)
            logger.debug(f"Parsed New MAC: {new_mac}")

        # Prefer "New MAC" as the primary result if available, otherwise "Current MAC".
        return new_mac if new_mac else current_mac, permanent_mac


    def get_current_mac(self, interface: str) -> Optional[str]:
        """
        Gets the current MAC address of the specified interface using 'macchanger -s'.

        Args:
            interface: The name of the network interface.

        Returns:
            The current MAC address as a string if successful, None otherwise.
        """
        if not self.macchanger_path: return None # macchanger not available
        if not interface_exists(interface):
            logger.error(f"Interface '{interface}' does not exist. Cannot get MAC address.")
            return None

        logger.info(f"Getting current MAC for interface '{interface}'.")
        # `macchanger -s` might return 0 even if it only shows Permanent MAC (e.g., if iface is down or unmanaged)
        # So, we don't use check_errors=True and instead parse carefully.
        success, stdout_str, stderr_str = self._run_command(['-s', interface], check_errors=False)

        if stdout_str: # Process output even if command had non-zero exit (e.g. if iface down)
            current, _ = self._parse_macchanger_output(stdout_str)
            if current:
                logger.info(f"Current MAC for '{interface}': {current}")
                return current.lower() # Standardize to lowercase
            else:
                logger.warning(f"Could not parse current MAC for '{interface}' from macchanger output. Stdout: '{stdout_str}', Stderr: '{stderr_str}'")
        else:
            logger.warning(f"Failed to get current MAC for '{interface}' (no output from macchanger). Stderr: '{stderr_str}'")
        return None

    def set_mac_random(self, interface: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Sets a random MAC address for the specified interface.
        The interface is temporarily brought down and then up during this process.

        Args:
            interface: The name of the network interface.

        Returns:
            A tuple (new_mac, permanent_mac). 'new_mac' is the randomly set MAC address.
            Returns (None, None) if the operation fails.
        """
        if not self.macchanger_path: return None, None
        if not interface_exists(interface):
            logger.error(f"Interface '{interface}' does not exist. Cannot set random MAC.")
            return None, None

        logger.info(f"Attempting to set a random MAC for interface '{interface}'.")
        original_mac = self.get_current_mac(interface)
        log_event_data = {"interface": interface, "old_mac": original_mac, "method": "random"}

        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface):
                interface_was_brought_down = True
            else:
                logger.warning(f"Failed to bring interface '{interface}' down. Attempting MAC change anyway, but it may fail.")

            success, stdout_str, stderr_str = self._run_command(['-r', interface])

            if success and stdout_str:
                new_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if new_mac:
                    logger.info(f"Successfully set random MAC for '{interface}' to '{new_mac}' (Permanent: {perm_mac}). Original was: {original_mac}")
                    log_event("mac_address_changed", {**log_event_data, "new_mac": new_mac, "permanent_mac": perm_mac})
                    return new_mac.lower(), perm_mac.lower() if perm_mac else None
                else:
                    logger.warning(f"Could not parse new MAC from 'macchanger -r' output for '{interface}'. Stdout: '{stdout_str}', Stderr: '{stderr_str}'")
                    log_event("mac_change_parse_failed", {**log_event_data, "output": stdout_str})
            else:
                logger.error(f"Failed to set random MAC for '{interface}'. Macchanger command stdout: '{stdout_str}', stderr: '{stderr_str}'")
                log_event("mac_change_failed", {**log_event_data, "reason": "macchanger command failed", "stdout": stdout_str, "stderr": stderr_str})
            return None, None
        finally:
            if interface_was_brought_down or not self._is_interface_up(interface): # Ensure interface is up
                if not self._bring_interface_up(interface):
                    logger.critical(f"CRITICAL: Interface '{interface}' was left down after set_mac_random attempt and could not be brought up.")
                    log_event("mac_change_interface_stuck_down", {**log_event_data, "interface_state": "down"})
                else:
                    logger.info(f"Interface '{interface}' brought back up after set_mac_random attempt.")


    def _is_interface_up(self, interface: str) -> bool:
        """Helper to check if interface is operationally UP using 'ip link show'."""
        if not interface_exists(interface): return False
        try:
            # Using system 'ip' command.
            result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True, check=True, timeout=5)
            # Check for 'state UP' in the output. Example: <BROADCAST,MULTICAST,UP,LOWER_UP> state UP
            return "state UP" in result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug(f"Could not determine if interface '{interface}' is up via 'ip link': {e}")
            return False # Unsure, assume not up for safety or try alternative
        except Exception as e_unexp:
            logger.error(f"Unexpected error checking interface UP state for '{interface}': {e_unexp}", exc_info=True)
            return False


    def set_mac_specific(self, interface: str, new_mac_address: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Sets a specific MAC address for the specified interface.
        The interface is temporarily brought down and then up during this process.

        Args:
            interface: The name of the network interface.
            new_mac_address: The new MAC address to set (e.g., "aa:bb:cc:dd:ee:ff").

        Returns:
            A tuple (changed_mac, permanent_mac). 'changed_mac' is the MAC address after the operation.
            Returns (None, None) if the operation fails.
        """
        if not self.macchanger_path: return None, None
        logger.info(f"Attempting to set MAC for interface '{interface}' to '{new_mac_address}'.")
        if not interface_exists(interface):
            logger.error(f"Interface '{interface}' does not exist. Cannot set specific MAC.")
            return None, None

        original_mac = self.get_current_mac(interface)
        log_event_data = {"interface": interface, "old_mac": original_mac, "requested_mac": new_mac_address, "method": "specific"}
        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface):
                interface_was_brought_down = True
            else:
                logger.warning(f"Failed to bring interface '{interface}' down. Attempting MAC change to '{new_mac_address}' anyway, but it may fail.")

            success, stdout_str, stderr_str = self._run_command(['-m', new_mac_address, interface])

            if success and stdout_str:
                changed_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if changed_mac and changed_mac.lower() == new_mac_address.lower():
                    logger.info(f"Successfully set MAC for '{interface}' to '{changed_mac}' (Permanent: {perm_mac}). Original was: {original_mac}")
                    log_event("mac_address_changed", {**log_event_data, "new_mac": changed_mac, "permanent_mac": perm_mac})
                elif changed_mac: # MAC changed, but not to what we asked.
                    logger.warning(f"MAC for '{interface}' changed to '{changed_mac}', not the requested '{new_mac_address}'. Permanent: {perm_mac}. Original was: {original_mac}")
                    log_event("mac_address_changed_unexpected", {**log_event_data, "actual_new_mac": changed_mac, "permanent_mac": perm_mac})
                else:
                    logger.warning(f"Could not parse new MAC from 'macchanger -m' output for '{interface}'. Stdout: '{stdout_str}', Stderr: '{stderr_str}'")
                    log_event("mac_change_parse_failed", {**log_event_data, "output": stdout_str})
                return changed_mac.lower() if changed_mac else None, perm_mac.lower() if perm_mac else None
            else:
                logger.error(f"Failed to set MAC for '{interface}' to '{new_mac_address}'. Macchanger stdout: '{stdout_str}', stderr: '{stderr_str}'")
                log_event("mac_change_failed", {**log_event_data, "reason": "macchanger command failed", "stdout": stdout_str, "stderr": stderr_str})
            return None, None
        finally:
            if interface_was_brought_down or not self._is_interface_up(interface):
                if not self._bring_interface_up(interface):
                    logger.critical(f"CRITICAL: Interface '{interface}' was left down after set_mac_specific attempt and could not be brought up.")
                    log_event("mac_change_interface_stuck_down", {**log_event_data, "interface_state": "down"})
                else:
                    logger.info(f"Interface '{interface}' brought back up after set_mac_specific attempt.")


    def revert_to_original_mac(self, interface: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Reverts the MAC address of the specified interface to its permanent hardware MAC.
        The interface is temporarily brought down and then up during this process.

        Args:
            interface: The name of the network interface.

        Returns:
            A tuple (reverted_mac, permanent_mac). 'reverted_mac' should match 'permanent_mac'.
            Returns (None, None) if the operation fails.
        """
        if not self.macchanger_path: return None, None
        logger.info(f"Attempting to revert MAC for interface '{interface}' to permanent hardware MAC.")
        if not interface_exists(interface):
            logger.error(f"Interface '{interface}' does not exist. Cannot revert MAC.")
            return None, None

        current_mac_before_revert = self.get_current_mac(interface)
        log_event_data = {"interface": interface, "reverted_from_mac": current_mac_before_revert, "method": "revert_to_permanent"}
        interface_was_brought_down = False
        try:
            if self._bring_interface_down(interface):
                interface_was_brought_down = True
            else:
                logger.warning(f"Failed to bring interface '{interface}' down. Attempting MAC reversion anyway, but it may fail.")

            success, stdout_str, stderr_str = self._run_command(['-p', interface])

            if success and stdout_str:
                reverted_mac, perm_mac = self._parse_macchanger_output(stdout_str)
                if reverted_mac and perm_mac and reverted_mac.lower() == perm_mac.lower():
                    logger.info(f"Successfully reverted MAC for '{interface}' to permanent MAC: '{reverted_mac}'. Previous MAC was: {current_mac_before_revert}")
                    log_event("mac_address_reverted", {**log_event_data, "reverted_to_mac": reverted_mac, "permanent_mac": perm_mac})
                elif reverted_mac:
                     logger.warning(f"MAC for '{interface}' reverted by 'macchanger -p' to '{reverted_mac}', but permanent MAC reported as '{perm_mac}'. Previous MAC: {current_mac_before_revert}")
                     log_event("mac_address_reverted_mismatch", {**log_event_data, "reverted_to_mac": reverted_mac, "permanent_mac": perm_mac})
                else:
                    logger.warning(f"Could not parse reverted MAC from 'macchanger -p' output for '{interface}'. Stdout: '{stdout_str}', Stderr: '{stderr_str}'")
                    log_event("mac_revert_parse_failed", {**log_event_data, "output": stdout_str})
                return reverted_mac.lower() if reverted_mac else None, perm_mac.lower() if perm_mac else None
            else:
                logger.error(f"Failed to revert MAC for '{interface}' to permanent hardware MAC. Macchanger stdout: '{stdout_str}', stderr: '{stderr_str}'")
                log_event("mac_revert_failed", {**log_event_data, "reason": "macchanger command failed", "stdout": stdout_str, "stderr": stderr_str})
            return None, None
        finally:
            if interface_was_brought_down or not self._is_interface_up(interface):
                if not self._bring_interface_up(interface):
                    logger.critical(f"CRITICAL: Interface '{interface}' was left down after revert_to_original_mac attempt and could not be brought up.")
                    log_event("mac_revert_interface_stuck_down", {**log_event_data, "interface_state": "down"})
                else:
                    logger.info(f"Interface '{interface}' brought back up after revert_to_original_mac attempt.")

if __name__ == '__main__':
    # --- Test Setup ---
    # This block is for testing the MACChanger class directly.
    # It requires:
    #   1. Root privileges (sudo python -m backend.plugins.opsec_utils)
    #   2. 'macchanger' and 'ip' commands installed and in PATH.
    #   3. A valid network interface name to test on.
    #      WARNING: This will change the MAC address of the specified interface.
    #               Use a test VM or a non-critical interface.

    # Configure basic logging for the test execution.
    # This setup ensures that logs from this module are clearly visible.
    logging.basicConfig(level=logging.DEBUG,
                        format="[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d (%(funcName)s)] %(message)s",
                        stream=sys.stdout) # Log to console for __main__ tests

    # Explicitly set this module's logger to DEBUG if it was set higher by root config.
    logging.getLogger(__name__).setLevel(logging.DEBUG)

    # --- Test Configuration ---
    # !!! IMPORTANT: CHANGE THIS TO A REAL, NON-CRITICAL INTERFACE FOR TESTING !!!
    # Using a virtual interface (e.g., one created with `sudo ip link add veth_test type veth peer name veth_test_peer`)
    # or an interface on a test VM is STRONGLY recommended.
    iface_to_test = "veth_test_mac_placeholder" # Example: "eth0", "wlan0", "veth_test_mac"

    logger.info(f"--- Starting MACChanger Test Suite on interface: '{iface_to_test}' ---")

    if "veth_test_mac_placeholder" == iface_to_test or not iface_to_test :
        logger.critical(f"CRITICAL TEST SETUP ERROR: 'iface_to_test' is still '{iface_to_test}'.")
        logger.critical("Please update this variable in the script to a real, non-critical network interface for testing.")
        logger.critical("Testing on a placeholder or empty interface name will fail or be meaningless.")
        logger.critical("Example: `sudo ip link add veth_test_mac type veth peer name veth_test_peer && sudo ip link set veth_test_mac up` then use 'veth_test_mac'.")
        sys.exit(1)

    changer = MACChanger()
    if not changer.macchanger_path: # Check if macchanger was found
        logger.error("'macchanger' command was not found by MACChanger class. Aborting tests.")
        logger.error("Please install 'macchanger' (e.g., 'sudo apt-get install macchanger') and ensure it's in the PATH.")
        sys.exit(1)

    if not interface_exists(iface_to_test):
        logger.error(f"Test interface '{iface_to_test}' does not exist. Aborting tests.")
        logger.error(f"Please ensure the interface '{iface_to_test}' is valid and configured on your system.")
        logger.error("If using a virtual interface like veth, ensure it has been created and brought up, e.g.:")
        logger.error(f"  sudo ip link add {iface_to_test} type veth peer name {iface_to_test}_peer && sudo ip link set {iface_to_test} up")
        sys.exit(1)

    logger.info(f"Target test interface '{iface_to_test}' exists. Proceeding with tests.")
    logger.warning("Ensure you are running this script with sudo/root privileges.")
    logger.warning(f"The MAC address of '{iface_to_test}' WILL BE MODIFIED during these tests.")

    # --- Test Execution ---
    initial_mac = changer.get_current_mac(iface_to_test)
    logger.info(f"Initial Current MAC for '{iface_to_test}': {initial_mac}")

    # Get Permanent MAC for reference (best effort, as parsing can be tricky)
    _, initial_stdout_s, _ = changer._run_command(['-s', iface_to_test], check_errors=False)
    _, permanent_mac_from_initial_s = changer._parse_macchanger_output(initial_stdout_s)
    if permanent_mac_from_initial_s:
        logger.info(f"Permanent MAC for '{iface_to_test}' (from initial 'macchanger -s'): {permanent_mac_from_initial_s}")
    else:
        logger.warning(f"Could not determine permanent MAC for '{iface_to_test}' from initial 'macchanger -s' output. Verification of revert might be limited.")

    if not initial_mac:
        logger.warning(f"Could not retrieve initial MAC for '{iface_to_test}'. Some test assertions might be skipped or less effective.")

    logger.info("\n--- Test 1: Set Random MAC ---")
    random_mac_set, perm_mac_after_random = changer.set_mac_random(iface_to_test)
    logger.info(f"set_mac_random returned: New MAC='{random_mac_set}', Permanent MAC='{perm_mac_after_random}'")
    current_mac_after_random = changer.get_current_mac(iface_to_test)
    logger.info(f"Current MAC after random set (queried again): {current_mac_after_random}")

    if random_mac_set and current_mac_after_random:
        assert random_mac_set.lower() == current_mac_after_random.lower(), \
            f"Assertion Failed: Random MAC set ({random_mac_set}) should match current MAC ({current_mac_after_random})!"
        if initial_mac: # Only assert if we have an initial MAC to compare against
             assert random_mac_set.lower() != initial_mac.lower(), \
                f"Assertion Failed: Random MAC ({random_mac_set}) should be different from initial MAC ({initial_mac})!"
        logger.info("Test 1 SUCCESS: Random MAC set and verified.")
    elif random_mac_set and not current_mac_after_random:
        logger.error("Test 1 FAILED: Random MAC was reportedly set, but get_current_mac failed afterwards.")
    else: # not random_mac_set
        logger.error("Test 1 FAILED: Failed to set or parse random MAC.")

    # Revert to permanent MAC before the specific MAC test to ensure a known state if possible.
    # Use the permanent MAC reported by the random change if available, otherwise the initial one.
    reliable_perm_mac_for_revert = perm_mac_after_random or permanent_mac_from_initial_s
    if reliable_perm_mac_for_revert:
        logger.info(f"\n--- Intermediate Revert to Permanent MAC ('{reliable_perm_mac_for_revert}') before specific MAC test ---")
        reverted_interim_mac, perm_mac_interim_revert = changer.revert_to_original_mac(iface_to_test)
        current_mac_after_interim_revert = changer.get_current_mac(iface_to_test)
        logger.info(f"Intermediate revert result: Reverted MAC='{reverted_interim_mac}', Permanent='{perm_mac_interim_revert}'")
        logger.info(f"Current MAC after intermediate revert (queried again): {current_mac_after_interim_revert}")
        if current_mac_after_interim_revert and perm_mac_interim_revert:
            assert current_mac_after_interim_revert.lower() == perm_mac_interim_revert.lower(), "Intermediate revert did not match reported permanent MAC."
            assert current_mac_after_interim_revert.lower() == reliable_perm_mac_for_revert.lower(), "Intermediate revert did not match target permanent MAC."
            logger.info("Intermediate revert to permanent MAC verified.")
        else:
            logger.warning("Could not fully verify intermediate revert due to missing MAC information.")
    else:
        logger.warning("Skipping intermediate revert as no reliable permanent MAC was determined from prior steps.")


    logger.info("\n--- Test 2: Set Specific MAC ---")
    specific_test_mac = "00:11:22:33:44:AA" # Using a distinct MAC for testing
    # Ensure specific_test_mac is different from current permanent MAC for a valid test
    if reliable_perm_mac_for_revert and specific_test_mac.lower() == reliable_perm_mac_for_revert.lower():
        specific_test_mac = "00:11:22:33:44:BB" # Choose a different one
        logger.info(f"Adjusted specific_test_mac to be different from permanent: {specific_test_mac}")

    logger.info(f"Attempting to set MAC to specific: '{specific_test_mac}'")
    specific_mac_set, perm_mac_after_specific = changer.set_mac_specific(iface_to_test, specific_test_mac)
    logger.info(f"set_mac_specific returned: New MAC='{specific_mac_set}', Permanent MAC='{perm_mac_after_specific}'")
    current_mac_after_specific = changer.get_current_mac(iface_to_test)
    logger.info(f"Current MAC after specific set (queried again): {current_mac_after_specific}")

    if specific_mac_set and current_mac_after_specific:
        assert specific_mac_set.lower() == specific_test_mac.lower(), \
            f"Assertion Failed: Specific MAC set ({specific_mac_set}) should match requested MAC ({specific_test_mac})!"
        assert current_mac_after_specific.lower() == specific_test_mac.lower(), \
            f"Assertion Failed: Current MAC ({current_mac_after_specific}) should match requested MAC ({specific_test_mac})!"
        logger.info("Test 2 SUCCESS: Specific MAC set and verified.")
    elif specific_mac_set and not current_mac_after_specific:
         logger.error("Test 2 FAILED: Specific MAC was reportedly set, but get_current_mac failed afterwards.")
    else: # not specific_mac_set
        logger.error("Test 2 FAILED: Failed to set or parse specific MAC.")

    # --- Final Revert to Original/Permanent MAC ---
    # Prefer the initially determined permanent MAC if available and seems consistent.
    final_target_perm_mac = permanent_mac_from_initial_s or perm_mac_after_specific or perm_mac_after_random
    if final_target_perm_mac:
        logger.info(f"\n--- Final Revert to Target Permanent MAC: '{final_target_perm_mac}' ---")
        final_reverted_mac, final_perm_mac_report = changer.revert_to_original_mac(iface_to_test)
        logger.info(f"Final revert command reported: Reverted MAC='{final_reverted_mac}', Permanent MAC='{final_perm_mac_report}'")
        current_mac_after_final_revert = changer.get_current_mac(iface_to_test)
        logger.info(f"Final current MAC after revert (queried again): {current_mac_after_final_revert}")

        if current_mac_after_final_revert and final_perm_mac_report:
            assert current_mac_after_final_revert.lower() == final_perm_mac_report.lower(), \
                "Final MAC check: Current MAC does not match the permanent MAC reported by the revert command!"
            # This assertion is the most critical for ensuring it reverted to *its* permanent.
            if final_perm_mac_report.lower() != final_target_perm_mac.lower():
                 logger.warning(f"Permanent MAC reported by final revert ('{final_perm_mac_report}') differs from the target permanent MAC ('{final_target_perm_mac}') determined earlier. This can happen if initial reads were imperfect.")
            assert current_mac_after_final_revert.lower() == final_target_perm_mac.lower(), \
                f"Final MAC check: Current MAC ({current_mac_after_final_revert}) does not match the target permanent MAC ({final_target_perm_mac})!"
            logger.info("Final revert to permanent MAC verified.")
        elif not current_mac_after_final_revert :
            logger.error("Critical: Failed to get final MAC address after attempting revert. Interface might be in an inconsistent state.")
        else: # current_mac_after_final_revert is set, but final_perm_mac_report is None
            logger.warning(f"Could not fully verify final MAC state. Current MAC is {current_mac_after_final_revert}, but permanent MAC from final revert was not parsed.")
            if current_mac_after_final_revert.lower() == final_target_perm_mac.lower():
                 logger.info("However, current MAC matches the target permanent MAC.")
            else:
                 logger.error(f"And current MAC {current_mac_after_final_revert} does not match target permanent {final_target_perm_mac}.")

    else:
        logger.warning("\nNo reliable permanent MAC was determined throughout tests to perform a targeted final revert check. Attempting generic revert.")
        changer.revert_to_original_mac(iface_to_test) # Attempt generic revert
        logger.info(f"Generic revert attempted. Final MAC is: {changer.get_current_mac(iface_to_test)}")


    logger.info("\n--- MACChanger Test Suite Completed ---")
    logger.info(f"Ensure interface '{iface_to_test}' is in the desired final state.")
    if permanent_mac_from_initial_s :
        logger.info(f"(It should ideally be '{permanent_mac_from_initial_s}' if all reverts were successful and consistent).")
