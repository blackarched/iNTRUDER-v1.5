"""
Network utility functions for checking interface status and properties.

Provides capabilities to verify if a network interface exists and to check
if a wireless interface is currently in monitor mode by invoking system
commands like 'ip' and 'iwconfig'.
"""
import subprocess
import logging
import re
import sys # For __main__ block logging configuration

# Initialize logger for this module
logger: logging.Logger = logging.getLogger(__name__)

def interface_exists(interface_name: str) -> bool:
    """
    Checks if a network interface exists on the system.

    Args:
        interface_name: The name of the network interface (e.g., "eth0", "wlan0").
                        An empty or non-string input will result in a False return.
    Returns:
        True if the interface exists, False otherwise or if an error occurs (e.g., 'ip' command not found).
    """
    if not interface_name or not isinstance(interface_name, str):
        logger.warning("Interface name provided is invalid (empty or not a string).")
        return False
    try:
        # Using 'ip link show' is a standard way to check for interface existence on modern Linux.
        process = subprocess.run(
            ["ip", "link", "show", interface_name],
            capture_output=True,
            text=True,        # Decodes stdout/stderr as text
            timeout=5,        # Prevents indefinite blocking
            encoding='utf-8', # Explicitly set encoding
            errors='ignore'   # Ignore decoding errors, though less likely for 'ip link show'
        )
        # A return code of 0 means the command executed successfully and the interface was found.
        if process.returncode == 0:
            logger.debug(f"Interface '{interface_name}' exists.")
            return True
        else:
            # Non-zero return code typically means the interface does not exist.
            # stderr might contain "Device "interface_name" does not exist."
            logger.debug(f"Interface '{interface_name}' does not exist or 'ip link show' command failed. "
                         f"RC: {process.returncode}, Stderr: {process.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout occurred while checking existence for interface '{interface_name}'.")
        return False
    except FileNotFoundError:
        # This means the 'ip' command itself was not found. This is a critical issue for this function.
        logger.error("'ip' command not found. This utility cannot check interface existence.", exc_info=True)
        # Depending on the application's overall requirements, this might warrant raising an exception
        # to signal a misconfigured environment. For now, returning False.
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred while checking existence for interface '{interface_name}': {e}", exc_info=True)
        return False

def is_monitor_mode(interface_name: str) -> bool:
    """
    Checks if a given wireless network interface is in monitor mode.

    This function first verifies if the interface exists. If it does, it then uses 'iwconfig'
    to determine if the interface is in "Monitor" mode.

    Args:
        interface_name: The name of the wireless interface (e.g., "wlan0mon").
                        An empty or non-string input will lead to an early False return
                        via the `interface_exists` check.
    Returns:
        True if the interface exists and is in monitor mode.
        False if the interface does not exist, is not wireless, is not in monitor mode,
        or if an error occurs (e.g., 'iwconfig' command not found).
    """
    if not interface_exists(interface_name):
        # The interface_exists function will log the reason (e.g., doesn't exist, invalid name).
        logger.warning(f"Cannot check monitor mode for '{interface_name}' as it does not exist or could not be verified.")
        return False

    try:
        # 'iwconfig' is the standard command to check wireless interface properties, including mode.
        process = subprocess.run(
            ["iwconfig", interface_name],
            capture_output=True,
            text=True,        # Decodes stdout/stderr as text
            timeout=5,        # Prevents indefinite blocking
            encoding='utf-8', # Explicitly set encoding
            errors='ignore'   # Important for iwconfig as output can sometimes have non-standard characters
        )

        if process.returncode == 0:
            # Successful execution of iwconfig. Now parse output for "Mode:Monitor".
            # Example output for monitor mode:
            #   wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.412 GHz  Tx-Power=20 dBm
            # Example for managed mode:
            #   wlan0     IEEE 802.11  ESSID:"MyNetwork"  Mode:Managed ...
            # Using regex to find "Mode:Monitor" case-insensitively.
            if re.search(r"Mode:Monitor", process.stdout, re.IGNORECASE):
                logger.info(f"Interface '{interface_name}' is in monitor mode.")
                return True
            else:
                # Interface exists and iwconfig ran, but "Mode:Monitor" not found.
                logger.info(f"Interface '{interface_name}' is not in monitor mode. "
                            f"Actual output from iwconfig (first 100 chars): '{process.stdout[:100].strip()}...'")
                return False
        else:
            # iwconfig can return a non-zero code for various reasons:
            # 1. Interface has no wireless extensions (e.g., 'lo', 'eth0'). This is common.
            # 2. Other operational errors.
            # stderr often contains "Interface doesn't support wireless extensions." or similar.
            logger.warning(f"'iwconfig {interface_name}' command failed or interface likely does not support wireless extensions. "
                         f"RC: {process.returncode}, Stderr: '{process.stderr.strip()}', Stdout: '{process.stdout.strip()}'")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout occurred while running 'iwconfig {interface_name}'.")
        return False
    except FileNotFoundError:
        # This means 'iwconfig' command was not found. Critical for this function's purpose.
        logger.error("'iwconfig' command not found. This utility cannot check monitor mode.", exc_info=True)
        # Similar to 'ip' command, may warrant raising an exception in some applications.
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred while checking monitor mode for '{interface_name}': {e}", exc_info=True)
        return False

if __name__ == '__main__':
    # --- Test Setup ---
    # Configure basic logging to see output from the logger used in functions.
    # This will print to console (stdout).
    logging.basicConfig(
        level=logging.DEBUG, # Set to INFO for less verbose output during normal use
        format="%(asctime)s [%(levelname)s] %(name)s (%(module)s.%(funcName)s): %(message)s",
        stream=sys.stdout  # Directs log output to standard out
    )

    logger.info("--- Starting Network Utilities Test Suite ---")
    # --- IMPORTANT TEST INSTRUCTIONS ---
    # The tests below rely on the actual state of network interfaces on the system
    # where this script is executed. The interface names provided in `test_interfaces_config`
    # are common placeholders.
    #
    # YOU MUST **ADAPT THESE PLACEHOLDER NAMES** to match the interfaces on YOUR system
    # for the tests to be meaningful for your specific environment.
    #
    # How to choose interfaces for testing:
    #   - 'loopback': Should generally be 'lo'. It always exists but is not wireless.
    #   - 'ethernet': An active wired ethernet interface (e.g., 'eth0', 'enp0s31f6').
    #                 If you don't have one, tests for it will (correctly) show non-existence.
    #   - 'wifi_managed': A Wi-Fi interface in normal "Managed" mode (connected or ready to connect).
    #                     (e.g., 'wlan0', 'wlp1s0').
    #   - 'wifi_monitor': A Wi-Fi interface that YOU HAVE MANUALLY PUT INTO "Monitor" MODE.
    #                     (e.g., by using airmon-ng: `sudo airmon-ng start wlan0` which might create `wlan0mon`).
    #                     This is essential for accurately testing the `is_monitor_mode` function.
    #
    # If an interface type is not available on your system, the corresponding tests will reflect that
    # (e.g., report as non-existent or not in monitor mode), which is the expected behavior.
    # --- END OF IMPORTANT TEST INSTRUCTIONS ---

    # Dictionary of interfaces to test. **MODIFY VALUES AS PER YOUR SYSTEM CONFIGURATION.**
    # Using clearly placeholder names to emphasize the need for user modification.
    test_interfaces_config = {
        "loopback": "lo",                           # Standard loopback interface, should always exist.
        "ethernet": "eth0_placeholder_rename_me",   # Replace with your Ethernet interface name (e.g., eth0, enp2s0)
        "wifi_managed": "wlan0_placeholder_rename_me", # Replace with your Wi-Fi interface in managed mode (e.g., wlan0)
        "wifi_monitor": "wlan0mon_placeholder_rename_me" # Replace with your Wi-Fi interface in monitor mode (e.g., wlan0mon)
    }

    logger.info("\n--- Phase 1: Testing interface_exists() ---")
    existence_status = {} # To store results for use in Phase 2, avoiding redundant checks
    for category, iface_name in test_interfaces_config.items():
        logger.info(f"Test (P1): Checking existence of '{iface_name}' (intended as {category})...")
        exists = interface_exists(iface_name)
        existence_status[iface_name] = exists
        if exists:
            logger.info(f"Result (P1): Interface '{iface_name}' ({category}) - EXISTS.")
        else:
            # This is a warning because for placeholder names, non-existence is likely until configured.
            logger.warning(f"Result (P1): Interface '{iface_name}' ({category}) - DOES NOT EXIST or error in check. "
                           f"If you expected '{iface_name}' to exist, please verify its name and system status. "
                           f"Ensure you've updated placeholder names in `test_interfaces_config`.")

    logger.info("\n--- Phase 2: Testing is_monitor_mode() ---")
    for category, iface_name in test_interfaces_config.items():
        logger.info(f"Test (P2): Checking monitor mode for '{iface_name}' (intended as {category})...")

        if not existence_status.get(iface_name):
            logger.warning(f"Result (P2): Skipping monitor mode check for '{iface_name}' ({category}) because it was not found or failed existence check in Phase 1.")
            continue

        # For 'loopback' and 'ethernet', we expect them not to be in monitor mode (or not wireless capable).
        if category in ["loopback", "ethernet"]:
            expected_mon_mode = False
        # For 'wifi_managed', we expect it not to be in monitor mode.
        elif category == "wifi_managed":
            expected_mon_mode = False
        # For 'wifi_monitor', we expect it to be in monitor mode.
        elif category == "wifi_monitor":
            expected_mon_mode = True
        else:
            logger.warning(f"Internal Test Warning: Unknown category '{category}' for interface '{iface_name}'. Cannot set expected monitor mode.")
            continue # Skip if category is somehow unknown

        is_mon = is_monitor_mode(iface_name)

        if is_mon:
            logger.info(f"Result (P2): Interface '{iface_name}' ({category}) - IS IN MONITOR MODE.")
            if not expected_mon_mode:
                logger.warning(f"  CHECK: Interface '{iface_name}' (intended as {category}) IS in monitor mode, but was expected NOT to be. "
                               "Verify interface configuration and test categories if this is surprising.")
        else:
            logger.info(f"Result (P2): Interface '{iface_name}' ({category}) - IS NOT IN MONITOR MODE (or is not wireless/error).")
            if expected_mon_mode:
                logger.warning(f"  CHECK: Interface '{iface_name}' (intended as {category}) IS NOT in monitor mode, but was expected TO BE. "
                               "Ensure it's correctly configured in monitor mode and an actual wireless interface for this test to pass as expected.")

    # --- Specific Assertions (Optional but Recommended for CI/Automated Testing) ---
    # If you have a definitive setup (e.g., a dedicated test VM or environment),
    # you can add assertions for interfaces you *know* should exist and be in a certain state.
    # Example:
    # actual_monitor_interface_name = test_interfaces_config["wifi_monitor"]
    # if "placeholder" not in actual_monitor_interface_name: # Only assert if not a placeholder
    #     logger.info(f"\n--- Specific Assertion for '{actual_monitor_interface_name}' (wifi_monitor) ---")
    #     if existence_status.get(actual_monitor_interface_name):
    #         assert is_monitor_mode(actual_monitor_interface_name), \
    #             f"CRITICAL TEST FAILURE: Interface '{actual_monitor_interface_name}' (configured as wifi_monitor) is NOT in monitor mode!"
    #         logger.info(f"Assertion SUCCESS: '{actual_monitor_interface_name}' is in monitor mode as expected.")
    #     else:
    #         logger.error(f"Assertion SKIPPED for '{actual_monitor_interface_name}': Interface does not exist. Cannot verify monitor mode.")
    # else:
    #     logger.warning("\nSkipping specific assertions for 'wifi_monitor' as its name still appears to be a placeholder.")


    logger.info("\n--- Network Utilities Test Suite Completed ---")
    logger.info("Reminder: For accurate and meaningful results, ensure interface names in "
                "'test_interfaces_config' were correctly adapted to your system's actual configuration.")
