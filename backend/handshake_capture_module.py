import subprocess
import logging
import time
import os
import re # For sanitizing SSID/BSSID in filenames
from typing import Optional, Dict, Any, List

# Attempt to import from local package structure
try:
    from . import config
    from .core.network_utils import interface_exists, is_monitor_mode
    from ..core.event_logger import log_event
except ImportError:
    # Fallback for direct execution or different environment setups (e.g. tests)
    # This assumes that 'config.py', 'core/network_utils.py', and 'core/event_logger.py'
    # might be discoverable in PYTHONPATH or current working directory.
    logger = logging.getLogger(__name__)
    logger.warning("Running HandshakeCapture with fallback imports. Ensure necessary modules (config, core.network_utils, core.event_logger) are accessible.")
    import config # type: ignore
    from core.network_utils import interface_exists, is_monitor_mode # type: ignore
    from core.event_logger import log_event # type: ignore


logger = logging.getLogger(__name__)

class HandshakeCapture:
    """
    Manages the process of capturing wireless handshakes using airodump-ng.

    This class handles the setup, execution, and termination of an airodump-ng process
    to capture EAPOL handshakes (often WPA/WPA2 four-way handshakes). It can target
    specific SSIDs or BSSIDs on a given wireless channel and saves the capture
    to a file. It also logs significant events using the event_logger.
    """

    def __init__(self,
                 iface: str,
                 ssid: Optional[str] = None,
                 bssid: Optional[str] = None,
                 channel: Optional[int] = None,
                 output_dir: Optional[str] = None,
                 file_prefix: Optional[str] = None):
        """
        Initializes the HandshakeCapture instance.

        Args:
            iface: The name of the wireless interface to use for capture.
                   This interface *must* be in monitor mode for effective capture.
            ssid: The SSID (network name) of the target network.
                  If provided, airodump-ng will filter for this SSID.
            bssid: The BSSID (MAC address) of the target access point.
                   If provided, airodump-ng will filter for this BSSID (this is generally
                   more specific and preferred for targeted captures).
            channel: The wireless channel number of the target network.
                     If not provided, airodump-ng might hop channels, which is less
                     effective for specific AP targeting.
            output_dir: Directory where capture files will be saved.
                        Defaults to `config.HANDSHAKE_CAPTURE_DIR` from the application config.
            file_prefix: Prefix for the capture filenames.
                         Defaults to `config.HANDSHAKE_CAPTURE_PREFIX` from the application config.

        Raises:
            OSError: If the output directory (either specified or from config) cannot be created.
        """
        self.iface: str = iface
        self.ssid: Optional[str] = ssid
        self.bssid: Optional[str] = bssid
        self.channel: Optional[int] = channel

        # Use configured defaults if parameters are not provided
        self.output_dir: str = output_dir if output_dir is not None else config.HANDSHAKE_CAPTURE_DIR
        effective_file_prefix: str = file_prefix if file_prefix is not None else config.HANDSHAKE_CAPTURE_PREFIX

        self.process: Optional[subprocess.Popen] = None # To store the running airodump-ng process

        # Ensure output directory exists. This is done once.
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            logger.debug(f"Output directory for captures ensured: {self.output_dir}")
        except OSError as e:
            # Log and re-raise if directory creation fails, as it's critical.
            logger.error(f"Fatal: Could not create output directory '{self.output_dir}'. Error: {e}", exc_info=True)
            raise

        # Generate a unique filename base for this capture session. This is done once.
        target_name_part: str = "any_target" # Default if no SSID/BSSID
        if self.bssid:
            # Sanitize BSSID for use in filename (remove colons, make uppercase)
            target_name_part = re.sub(r'[^a-zA-Z0-9]', '', self.bssid).upper()
        elif self.ssid:
            # Sanitize SSID for filename: replace non-alphanumeric characters with underscore
            sanitized_ssid = re.sub(r'\W+', '_', self.ssid) # Replace one or more non-alphanumeric with single _
            target_name_part = sanitized_ssid[:30] # Limit length to keep filenames manageable

        timestamp: str = time.strftime('%Y%m%d_%H%M%S') # Consistent timestamp format
        self.filename_base: str = f"{effective_file_prefix}_{target_name_part}_{timestamp}"

        # self.cap_file_path is the primary .cap file airodump-ng is instructed to create.
        # Airodump-ng might also create other files (e.g., base-01.cap, .csv files) using this base name.
        self.cap_file_path: str = os.path.join(self.output_dir, f"{self.filename_base}.cap")

        logger.info(f"HandshakeCapture initialized for iface '{self.iface}'. Target SSID: '{self.ssid}', BSSID: '{self.bssid}', Channel: {self.channel}.")
        logger.info(f"Output directory: '{self.output_dir}', Filename base: '{self.filename_base}' (e.g., {self.cap_file_path})")


    def capture(self, timeout: int = 120) -> Dict[str, Any]:
        """
        Starts the airodump-ng capture process for a specified duration.

        Checks for interface existence and monitor mode status before starting.
        Manages the airodump-ng subprocess, including timed termination and error handling.
        Logs significant events using `log_event`.

        Args:
            timeout: Duration in seconds to run the capture. Defaults to 120 seconds (2 minutes).

        Returns:
            A dictionary summarizing the capture attempt:
            {
                "status": "success" | "success_with_errors" | "error",
                "message": "Descriptive message of the outcome.",
                "file": "/path/to/capture.cap" (if successful or partially successful),
                "command": ["executed", "command", "list"],
                "stdout": "stdout from airodump-ng",
                "stderr": "stderr from airodump-ng",
                "return_code": integer_exit_code_or_None
            }
        """
        base_event_data = {
            "interface": self.iface, "ssid": self.ssid, "bssid": self.bssid, "channel": self.channel,
            "output_dir": self.output_dir, "filename_base": self.filename_base, "requested_timeout": timeout
        }
        logger.info(f"Attempting handshake capture: {base_event_data}")

        if not interface_exists(self.iface):
            msg = f"Interface '{self.iface}' does not exist. Cannot start capture."
            logger.error(msg)
            log_event("handshake_capture_failed", {**base_event_data, "reason": msg, "details": "Interface check failed"})
            return {"status": "error", "message": msg, "command": ["airodump-ng", self.iface, "..."]}

        if not is_monitor_mode(self.iface):
            msg = f"Interface '{self.iface}' is not in monitor mode. Handshake capture effectiveness will be significantly reduced or may fail entirely."
            logger.warning(msg)
            # Log a warning event, but proceed as airodump-ng might still run (though often ineffectively without monitor mode).
            log_event("handshake_capture_warning", {**base_event_data, "reason": msg, "details": "Monitor mode check failed"})
            # Depending on strictness, one might choose to return an error here:
            # return {"status": "error", "message": msg, "command": ["airodump-ng", self.iface, "..."]}

        # Construct the airodump-ng command
        # The --write argument takes a prefix; airodump-ng appends extensions like .cap, .csv.
        # We ensure this path is within our designated output directory.
        airodump_write_prefix = os.path.join(self.output_dir, self.filename_base)

        cmd: List[str] = [
            "airodump-ng",
            self.iface,
            "--write", airodump_write_prefix,
            "--output-format", "pcap,csv", # Request pcap (for handshakes) and csv (for general info)
        ]

        if self.bssid: # Targeting a specific BSSID is most effective
            cmd.extend(["--bssid", self.bssid])
        elif self.ssid: # Fallback to SSID if BSSID not known
            cmd.extend(["--essid", self.ssid])
        # If neither BSSID nor SSID is given, airodump-ng captures from all APs it sees.

        if self.channel:
            cmd.extend(["--channel", str(self.channel)])
        else:
            # No channel specified: airodump-ng will hop. This is generally not ideal for
            # capturing a handshake from a specific target quickly.
            logger.warning("No channel specified for capture; airodump-ng will channel hop. This may reduce handshake capture success for a specific target.")
            log_event("handshake_capture_info", {**base_event_data, "details": "No channel specified, airodump-ng will hop."})

        logger.info(f"Constructed airodump-ng command: {' '.join(cmd)}")
        log_event("handshake_capture_started", {**base_event_data, "command": ' '.join(cmd)})

        stdout_str: str = ""
        stderr_str: str = ""
        return_code: Optional[int] = None

        try:
            # Start the airodump-ng process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, # Decodes stdout/stderr to text
                encoding='utf-8',
                errors='ignore' # airodump-ng can output non-UTF8 chars from SSIDs/device names
            )
            pid = self.process.pid
            logger.info(f"Airodump-ng process (PID: {pid}) started. Capturing for up to {timeout} seconds...")
            base_event_data["pid"] = pid # Add PID for subsequent event logs related to this process

            try:
                # Wait for the process to complete or timeout
                stdout_str, stderr_str = self.process.communicate(timeout=timeout)
                return_code = self.process.returncode
                logger.info(f"Airodump-ng (PID: {pid}) completed before timeout. Exit code: {return_code}.")
            except subprocess.TimeoutExpired:
                logger.info(f"Capture duration of {timeout}s reached. Terminating airodump-ng (PID: {pid}).")
                log_event("handshake_capture_terminating", {**base_event_data, "reason": "Timeout reached"})
                self.process.terminate() # Send SIGTERM
                try:
                    # Wait for graceful termination and collect final output
                    stdout_str_term, stderr_str_term = self.process.communicate(timeout=15) # Allow time for cleanup
                    stdout_str += stdout_str_term
                    stderr_str += stderr_str_term
                    return_code = self.process.returncode
                    logger.info(f"Airodump-ng (PID: {pid}) terminated. Exit code: {return_code}.")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Airodump-ng (PID: {pid}) did not terminate gracefully after 15s. Killing.")
                    log_event("handshake_capture_killing", {**base_event_data, "reason": "Did not terminate gracefully after SIGTERM"})
                    self.process.kill() # Send SIGKILL
                    try:
                        # Attempt to get any final output after kill
                        stdout_str_kill, stderr_str_kill = self.process.communicate(timeout=5)
                        stdout_str += stdout_str_kill
                        stderr_str += stderr_str_kill
                    except Exception: # pylint: disable=broad-except
                        pass # Ignore errors here, process is being forcefully killed
                    return_code = self.process.wait() # Get final return code after kill
                    logger.info(f"Airodump-ng (PID: {pid}) killed. Exit code: {return_code}.")
                except Exception as e_comm_term: # pylint: disable=broad-except
                    logger.error(f"Error communicating with terminated PID {pid}: {e_comm_term}", exc_info=True)
                    return_code = self.process.poll() if self.process.poll() is not None else -98 # Arbitrary error code

            if stdout_str:
                logger.debug(f"Final airodump-ng stdout (PID {pid}):\n{stdout_str.strip()}")
            if stderr_str: # airodump-ng often uses stderr for status messages and errors
                logger.debug(f"Final airodump-ng stderr (PID {pid}):\n{stderr_str.strip()}")

            # File checking: airodump-ng might create multiple files (e.g., base-01.cap, base-02.cap)
            # We are primarily interested in any .cap file starting with our filename_base.
            # The most relevant one is often the one with the highest number if split, or the direct one.
            created_cap_files = [
                f for f in os.listdir(self.output_dir)
                if f.startswith(self.filename_base) and f.endswith(".cap") and os.path.isfile(os.path.join(self.output_dir, f))
            ]

            if not created_cap_files:
                msg = f"No .cap file starting with '{self.filename_base}' found in '{self.output_dir}' after airodump-ng execution."
                logger.error(msg + (f" Airodump-ng STDERR: {stderr_str.strip()}" if stderr_str else ""))
                log_event("handshake_capture_failed", {
                    **base_event_data, "reason": "Capture .cap file not found",
                    "stderr": stderr_str.strip(), "return_code": return_code
                })
                return {"status": "error", "message": msg, "command": cmd, "stdout": stdout_str, "stderr": stderr_str, "return_code": return_code}

            # If multiple .cap files (e.g., base-01.cap, base-02.cap), pick the last one by name sort.
            final_cap_path = os.path.join(self.output_dir, sorted(created_cap_files)[-1])
            logger.info(f"Located primary capture file: {final_cap_path}")

            # Check file size; an empty .cap file is not useful.
            if os.path.getsize(final_cap_path) == 0:
                msg = f"Capture file '{final_cap_path}' is empty. No handshake likely captured."
                logger.warning(msg)
                log_event("handshake_capture_warning", {
                     **base_event_data, "reason": "Capture file empty", "file": final_cap_path,
                     "stderr": stderr_str.strip(), "return_code": return_code
                })
                # This could be 'success_with_errors' or 'error' depending on strictness
                return {"status": "success_with_errors", "file": final_cap_path, "message": msg, "command": cmd, "stdout": stdout_str, "stderr": stderr_str, "return_code": return_code}

            # A non-zero return code might be due to SIGTERM (if timed out).
            # If a valid (non-empty) .cap file exists, it's usually considered a success or partial success.
            if return_code == 0:
                logger.info(f"Handshake capture process completed successfully. File: {final_cap_path}")
                log_event("handshake_capture_success", {**base_event_data, "file": final_cap_path, "return_code": return_code})
                return {"status": "success", "file": final_cap_path, "message": "Capture completed successfully.", "command": cmd, "stdout": stdout_str, "stderr": stderr_str, "return_code": return_code}
            else:
                msg = f"Airodump-ng exited with code {return_code}. Capture file '{final_cap_path}' was found and is non-empty."
                logger.warning(msg)
                log_event("handshake_capture_success_with_errors", {
                    **base_event_data, "file": final_cap_path, "return_code": return_code,
                    "stderr": stderr_str.strip(), "stdout": stdout_str.strip(), "reason": msg
                })
                return {"status": "success_with_errors", "file": final_cap_path, "message": msg + f" Stderr may contain details: {stderr_str.strip()}", "command": cmd, "stdout": stdout_str, "stderr": stderr_str, "return_code": return_code}

        except FileNotFoundError:
            # This means 'airodump-ng' command itself was not found.
            msg = "'airodump-ng' command not found. Please ensure aircrack-ng suite is installed and in system PATH."
            logger.error(msg, exc_info=True) # exc_info=True adds stack trace to log
            log_event("handshake_capture_failed", {**base_event_data, "reason": "airodump-ng command not found"})
            return {"status": "error", "message": msg, "command": cmd if 'cmd' in locals() else ['airodump-ng']}
        except Exception as e: # Catch any other unexpected errors
            msg = f"An unexpected error occurred during handshake capture: {str(e)}"
            # Use locals() to safely access cmd if it was defined before the exception
            command_executed = cmd if 'cmd' in locals() else ['airodump-ng (command construction failed)']
            logger.error(msg + f" Command: '{' '.join(command_executed)}'", exc_info=True)

            # Try to get final output/return code if process object exists
            stdout_final_exc, stderr_final_exc = stdout_str, stderr_str
            rc_final_exc = return_code
            if self.process and self.process.poll() is None: # If Popen started but error occurred outside .communicate()
                try:
                    s_o, s_e = self.process.communicate(timeout=1) # Short timeout to get final output
                    stdout_final_exc += s_o; stderr_final_exc += s_e
                    rc_final_exc = self.process.returncode
                except Exception: # pylint: disable=broad-except
                    pass # Best effort, don't let this mask the original exception

            log_event("handshake_capture_failed", {
                **base_event_data, "reason": f"Unexpected exception: {str(e)}",
                "stdout": stdout_final_exc.strip(), "stderr": stderr_final_exc.strip(), "return_code": rc_final_exc,
                "exception_type": type(e).__name__
            })
            return {"status": "error", "message": msg, "command": command_executed, "stdout": stdout_final_exc, "stderr": stderr_final_exc, "return_code": rc_final_exc}
        finally:
            # Ensure the process is cleaned up if it's still running and self.process was set
            if self.process and self.process.poll() is None:
                pid = self.process.pid # Get PID before self.process is cleared
                logger.warning(f"Airodump-ng process (PID {pid}) appears to be still running in `finally` block. Attempting to terminate.")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5) # Short wait for terminate
                except subprocess.TimeoutExpired:
                    logger.warning(f"Airodump-ng (PID {pid}) did not terminate after 5s in `finally`. Killing.")
                    self.process.kill()
                    try: self.process.wait(timeout=5) # Wait for kill
                    except Exception: pass # pylint: disable=broad-except
                except Exception: pass # pylint: disable=broad-except
            self.process = None # Clear self.process once Popen object is handled or was never fully started


    def shutdown(self) -> None:
        """
        Stops an active airodump-ng capture process, if one is running.

        This method is typically called to prematurely end a capture (e.g., by user action)
        or as part of a cleanup routine. It sends SIGTERM and then SIGKILL if necessary.
        """
        if self.process and self.process.poll() is None: # Check if a Popen object exists and is running
            pid = self.process.pid # Store PID for logging before self.process might be cleared
            logger.info(f"Shutdown called: attempting to stop active handshake capture process (PID: {pid})...")
            log_event("handshake_capture_shutdown_initiated", {
                "interface": self.iface, "pid": pid, "reason": "Explicit shutdown call",
                "filename_base": self.filename_base, "ssid": self.ssid, "bssid": self.bssid
            })
            self.process.terminate() # Send SIGTERM first for graceful shutdown
            try:
                self.process.wait(timeout=15) # Allow up to 15 seconds for graceful exit
                logger.info(f"Handshake capture process (PID: {pid}) terminated successfully on shutdown call (exit code {self.process.returncode}).")
                log_event("handshake_capture_shutdown_complete", {"pid": pid, "exit_code": self.process.returncode, "method": "terminate"})
            except subprocess.TimeoutExpired:
                logger.warning(f"Handshake capture process (PID: {pid}) did not terminate gracefully after 15s (SIGTERM). Sending SIGKILL.")
                self.process.kill() # Force kill if terminate didn't work
                try:
                    self.process.wait(timeout=5) # Wait for kill to complete
                    logger.info(f"Handshake capture process (PID: {pid}) killed on shutdown call (exit code {self.process.returncode}).")
                    log_event("handshake_capture_shutdown_complete", {"pid": pid, "exit_code": self.process.returncode, "method": "kill"})
                except subprocess.TimeoutExpired:
                    logger.error(f"Failed to get return code for killed PID {pid} during shutdown even after SIGKILL.")
                    log_event("handshake_capture_shutdown_failed", {"pid": pid, "reason": "Failed to get exit code after SIGKILL"})
                except Exception as e_wait_kill: # pylint: disable=broad-except
                    logger.error(f"Error waiting for killed PID {pid} to exit: {e_wait_kill}", exc_info=True)
                    log_event("handshake_capture_shutdown_error", {"pid": pid, "error": str(e_wait_kill)})

            except Exception as e_wait: # pylint: disable=broad-except
                 logger.error(f"Error waiting for handshake capture process (PID {pid}) to stop during shutdown: {e_wait}", exc_info=True)
                 log_event("handshake_capture_shutdown_error", {"pid": pid, "error": str(e_wait)})
            self.process = None # Clear the process attribute as it's no longer managed
        else:
            logger.info("HandshakeCapture shutdown: No active capture process found or process already terminated.")
            # log_event("handshake_capture_shutdown_noop", {"reason": "No active process"}) # Optional: log if no-op


# Example Usage (for testing this module directly)
if __name__ == '__main__':
    # --- Test Setup ---
    # Configure basic logging to see output from the module's logger and event_logger.
    import sys # Required for sys.stdout and sys.exit
    # Ensure re is available if this block is run standalone and class uses it.
    # import re # Already imported globally in the class file.

    logging.basicConfig(
        level=logging.DEBUG, # Set to INFO for less verbose output during normal use
        format="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d %(funcName)s): %(message)s",
        stream=sys.stdout  # Directs log output to standard out for easy viewing
    )
    logger.info("--- Starting Handshake Capture Module Test ---")

    # --- IMPORTANT: Test Prerequisites ---
    # 1. Root Privileges: This script MUST be run as root (or with `sudo`) to use airodump-ng
    #    and manage network interfaces. Example: `sudo python -m backend.handshake_capture_module`
    # 2. Monitor Mode Interface: You NEED a wireless interface already in MONITOR MODE.
    #    - List interfaces: `iwconfig` or `ip link show`
    #    - Create monitor interface (if `wlan0` is your card): `sudo airmon-ng start wlan0`
    #      This might create an interface like `wlan0mon` or `mon0`.
    #    - Verify mode: `iwconfig <monitor_interface_name>`. Output should include "Mode:Monitor".
    # 3. Aircrack-ng Suite: Ensure `airodump-ng` (and related tools) are installed and in your system's PATH.
    # 4. Target Network (Optional but Recommended): For best results, have a known Wi-Fi network
    #    nearby to target specifically. This makes testing more predictable.
    # ---

    # ** MODIFY THESE VALUES FOR YOUR ACTUAL TEST ENVIRONMENT **
    # Replace "mon0_placeholder" with your actual monitor mode interface name (e.g., "wlan0mon").
    # An invalid or non-monitor mode interface will cause tests to fail or behave unexpectedly.
    monitor_interface_name: str = "mon0_placeholder"

    # Optionally, target a specific SSID or BSSID. Using a BSSID is more precise.
    # If targeting a specific AP, also set its channel if known for faster, more reliable capture.
    target_ssid_optional: Optional[str] = "MyHomeNetworkSSID"  # Example: Your home Wi-Fi SSID
    target_bssid_optional: Optional[str] = None                # Example: "AA:BB:CC:DD:EE:FF" (MAC of your AP)
    target_channel_optional: Optional[int] = None              # Example: 6 (Channel of your AP, if known)

    capture_duration_seconds: int = 25 # Keep relatively short for testing purposes

    # --- Pre-run Checks (Essential for meaningful test) ---
    logger.info(f"--- Pre-run System Checks ---")
    logger.info(f"Attempting to use interface: '{monitor_interface_name}'")
    logger.info(f"Targeting SSID: '{target_ssid_optional}', BSSID: '{target_bssid_optional}', Channel: {target_channel_optional}")
    logger.info(f"Requested capture duration: {capture_duration_seconds} seconds.")

    if "mon0_placeholder" == monitor_interface_name or not monitor_interface_name:
        logger.critical("CRITICAL TEST SETUP ERROR: 'monitor_interface_name' is still a placeholder or is empty.")
        logger.critical("Please update this variable in the script to your actual wireless interface in monitor mode.")
        logger.critical("Aborting test. Refer to 'Test Prerequisites' at the top of this `if __name__ == '__main__':` block for guidance.")
        sys.exit(1) # Exit if placeholder is not changed

    if not interface_exists(monitor_interface_name):
        logger.critical(f"CRITICAL TEST SETUP ERROR: The specified monitor interface '{monitor_interface_name}' does not exist on this system.")
        logger.critical("Please verify the interface name and ensure it is active. Use `iwconfig` or `ip a` to check.")
        sys.exit(1) # Exit if interface doesn't exist

    if not is_monitor_mode(monitor_interface_name):
        logger.warning(f"WARNING: Interface '{monitor_interface_name}' does NOT appear to be in monitor mode.")
        logger.warning("`airodump-ng` will likely fail to capture handshakes or may not operate correctly.")
        logger.warning("Proceeding with the test, but EXPECT POTENTIAL ISSUES. For valid results, ensure the interface is in monitor mode.")
        # For a strict test, you might want to automatically abort here:
        # logger.critical("Aborting test because the interface is not in monitor mode.")
        # sys.exit(1)
    else:
        logger.info(f"Interface '{monitor_interface_name}' successfully passed monitor mode check (or the check itself passed).")


    # --- Test Execution ---
    logger.info(f"\n--- Initializing HandshakeCapture ---")
    capture_instance = HandshakeCapture(
        iface=monitor_interface_name,
        ssid=target_ssid_optional,
        bssid=target_bssid_optional,
        channel=target_channel_optional
        # Example: Override default output directory: output_dir="test_captures_custom"
        # Example: Override default file prefix: file_prefix="test_run_prefix_"
    )

    logger.info(f"HandshakeCapture instance created. Output will be in directory: '{capture_instance.output_dir}'")
    logger.info(f"Capture files will use base name: '{capture_instance.filename_base}' (e.g., {capture_instance.cap_file_path})")

    capture_result: Dict[str, Any] = {} # Initialize to store the outcome
    logger.info(f"\n--- Starting Capture (timeout: {capture_duration_seconds}s) ---")
    try:
        capture_result = capture_instance.capture(timeout=capture_duration_seconds)
        logger.info(f"Capture method finished. Result dictionary: {capture_result}")
    except Exception as e_capture: # pylint: disable=broad-except
        # This catches exceptions from the capture() call itself, not just from airodump-ng.
        logger.error(f"An unexpected exception occurred directly within the `capture_instance.capture()` call: {e_capture}", exc_info=True)
        capture_result = {"status": "exception_in_test_harness", "message": str(e_capture), "details": "Error in __main__ test code calling capture()"}
    finally:
        # Crucial: Ensure shutdown is called even if capture() fails or is interrupted (e.g., Ctrl+C).
        logger.info("Executing `finally` block: Calling shutdown() on HandshakeCapture instance...")
        capture_instance.shutdown() # This will handle stopping airodump-ng if it's running.

    # --- Test Results Analysis and Cleanup ---
    logger.info(f"\n--- Test Capture Summary ---")
    logger.info(f"Final Capture Status Reported: {capture_result.get('status')}")
    logger.info(f"Message from Capture Method: {capture_result.get('message')}")

    # Collect all files that might have been created to guide cleanup.
    final_capture_files_to_review: List[str] = []
    # Check the file path reported by the capture method
    reported_file_path = capture_result.get("file")
    if reported_file_path and isinstance(reported_file_path, str) and os.path.exists(reported_file_path):
        logger.info(f"Main handshake capture file (.cap) reported by method and exists: {reported_file_path}")
        if reported_file_path not in final_capture_files_to_review:
             final_capture_files_to_review.append(reported_file_path)
    else:
        logger.warning("No primary .cap file path was reported in the result, or the reported file does not exist.")
        # Even if not in result, check the initially constructed cap_file_path for diagnostic purposes.
        if os.path.exists(capture_instance.cap_file_path):
             logger.info(f"  However, the initially expected cap file path '{capture_instance.cap_file_path}' does exist.")
             if capture_instance.cap_file_path not in final_capture_files_to_review:
                 final_capture_files_to_review.append(capture_instance.cap_file_path)

    # Airodump-ng with "--output-format pcap,csv" can create multiple files (e.g., .cap, .csv, kismet.csv, kismet.netxml).
    # Scan the output directory for all files that start with the generated filename_base.
    logger.info(f"\nScanning output directory '{capture_instance.output_dir}' for all files related to base '{capture_instance.filename_base}':")
    if os.path.isdir(capture_instance.output_dir): # Check if directory exists before listing
        found_associated_files_count = 0
        for f_name in sorted(os.listdir(capture_instance.output_dir)):
            if f_name.startswith(capture_instance.filename_base):
                full_path = os.path.join(capture_instance.output_dir, f_name)
                try:
                    file_size = os.path.getsize(full_path)
                    logger.info(f"  - Found associated file: {full_path} (Size: {file_size} bytes)")
                except OSError:
                     logger.info(f"  - Found associated file: {full_path} (Size: Error reading size)")
                if full_path not in final_capture_files_to_review: # Add if not already listed
                    final_capture_files_to_review.append(full_path)
                found_associated_files_count +=1
        if not found_associated_files_count:
            logger.info(f"  No files starting with base '{capture_instance.filename_base}' found in the output directory.")
    else:
        logger.warning(f"Output directory '{capture_instance.output_dir}' does not exist or is not a directory. No files to list or clean up.")

    # File Cleanup Instructions
    if final_capture_files_to_review:
        logger.info("\n--- File Cleanup Guidance ---")
        logger.info("The following files were potentially created during this test run:")
        for f_path in final_capture_files_to_review:
            logger.info(f"  - {f_path}")

        # For this exercise, we will emphasize manual cleanup.
        # In a fully automated CI environment, you would uncomment and use os.remove().
        logger.warning("ACTION REQUIRED: MANUAL CLEANUP of the files listed above is recommended.")
        logger.warning(f"Please inspect the directory: '{capture_instance.output_dir}'")
        logger.warning(f"Look for files starting with the base name: '{capture_instance.filename_base}'")

        # Example of cleanup code (currently disabled for safety in manual testing):
        # print("\n--- AUTOMATED CLEANUP (CURRENTLY DISABLED) ---")
        # choice = input("Do you want to attempt to delete these files? (yes/No): ")
        # if choice.lower() == 'yes':
        #     for f_path_to_delete in final_capture_files_to_review:
        #         try:
        #             os.remove(f_path_to_delete)
        #             logger.info(f"Successfully removed: {f_path_to_delete}")
        #         except OSError as e_remove:
        #             logger.error(f"Error removing file {f_path_to_delete}: {e_remove}")
        # else:
        #     logger.info("Automated file cleanup skipped by user.")
    else:
        logger.info("\nNo capture files seem to have been created or found during this test run.")

    logger.info("\n--- Handshake Capture Module Test Finished ---")
    logger.info("Review logs above for detailed outcomes and any warnings/errors.")
