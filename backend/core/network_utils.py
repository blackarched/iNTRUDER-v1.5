import subprocess
import logging
import re

logger = logging.getLogger(__name__)

def interface_exists(interface_name: str) -> bool:
    """Checks if a network interface exists."""
    if not interface_name or not isinstance(interface_name, str):
        logger.warning("Interface name provided is invalid or empty.")
        return False
    try:
        # Using 'ip link show' is generally preferred over 'ifconfig' or '/sys/class/net' for modern Linux.
        # We don't need to check_errors=True here, as a non-zero return code means it doesn't exist or other error.
        process = subprocess.run(
            ["ip", "link", "show", interface_name],
            capture_output=True, text=True, timeout=5
        )
        if process.returncode == 0:
            logger.debug(f"Interface {interface_name} exists.")
            return True
        else:
            # stderr might contain "Device "interface_name" does not exist." or other info.
            logger.debug(f"Interface {interface_name} does not exist or 'ip link show' failed. RC: {process.returncode}, Error: {process.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout checking existence for interface {interface_name}.")
        return False
    except FileNotFoundError:
        logger.error("'ip' command not found. Cannot check interface existence.", exc_info=True)
        return False # Or raise an exception if 'ip' is critical for the whole app
    except Exception as e:
        logger.error(f"An unexpected error occurred while checking existence for interface {interface_name}: {e}", exc_info=True)
        return False

def is_monitor_mode(interface_name: str) -> bool:
    """Checks if a network interface is in monitor mode using iwconfig."""
    if not interface_exists(interface_name):
        logger.warning(f"Cannot check monitor mode: Interface {interface_name} does not exist.")
        return False

    try:
        # Using 'iwconfig interface_name'
        process = subprocess.run(
            ["iwconfig", interface_name],
            capture_output=True, text=True, timeout=5, encoding='utf-8', errors='ignore'
        )

        if process.returncode == 0:
            # Example output for monitor mode:
            # wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.412 GHz  Tx-Power=20 dBm
            #          Retry short limit:7   RTS thr:off   Fragment thr:off
            #          Power Management:off
            # Or for non-monitor:
            # wlan0     IEEE 802.11  ESSID:"MyNetwork"
            #           Mode:Managed  Frequency:5.785 GHz  Access Point: X1:X2:X3:X4:X5:X6
            match = re.search(r"Mode:Monitor", process.stdout, re.IGNORECASE)
            if match:
                logger.info(f"Interface {interface_name} is in monitor mode.")
                return True
            else:
                logger.info(f"Interface {interface_name} is not in monitor mode. Output: {process.stdout.strip()}")
                return False
        else:
            # iwconfig might return non-zero if interface has no wireless extensions (e.g. eth0)
            # or other errors.
            logger.warning(f"'iwconfig {interface_name}' command failed or returned no useful mode info. RC: {process.returncode}, Error: {process.stderr.strip()}, Output: {process.stdout.strip()}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout running 'iwconfig {interface_name}'.")
        return False
    except FileNotFoundError:
        logger.error("'iwconfig' command not found. Cannot check monitor mode.", exc_info=True)
        return False # Or raise, as iwconfig is key for this check
    except Exception as e:
        logger.error(f"An unexpected error occurred while checking monitor mode for {interface_name}: {e}", exc_info=True)
        return False

if __name__ == '__main__':
    # Setup basic logging for the test
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # --- WARNING ---
    # These tests rely on actual interface names and states.
    # Replace with interfaces available on your test system.
    # e.g., a wired 'eth0', a wireless 'wlan0', and 'wlan0mon' if in monitor mode.
    # --- WARNING ---

    test_interfaces = {
        "loopback": "lo",  # Should exist, not wireless
        "ethernet": "eth0", # Replace if your ethernet is named differently, or skip if none
        "wifi_managed": "wlan0", # Replace with your WiFi interface name
        "wifi_monitor": "wlan0mon" # Replace with your monitor interface name (if active)
    }

    logger.info("--- Testing interface_exists ---")
    for name, iface in test_interfaces.items():
        logger.info(f"Checking existence of {name} ('{iface}'): {interface_exists(iface)}")

    logger.info("\n--- Testing is_monitor_mode ---")
    for name, iface in test_interfaces.items():
        # is_monitor_mode already calls interface_exists, but explicit check here helps context
        if interface_exists(iface):
            logger.info(f"Checking monitor mode for {name} ('{iface}'): {is_monitor_mode(iface)}")
        else:
            logger.info(f"Skipping monitor mode check for {name} ('{iface}') as it does not exist.")

    # Example of how to test a specific interface you expect to be in monitor mode
    # monitor_iface_to_verify = "wlan0mon" # CHANGE THIS
    # if interface_exists(monitor_iface_to_verify):
    #     assert is_monitor_mode(monitor_iface_to_verify) == True, f"{monitor_iface_to_verify} should be in monitor mode for this test!"
    #     logger.info(f"Test: {monitor_iface_to_verify} is in monitor mode as expected.")
    # else:
    #     logger.warning(f"Test: Monitor interface {monitor_iface_to_verify} not found, cannot verify monitor mode assertion.")

    logger.info("\n--- Network Utils Test Completed ---")
