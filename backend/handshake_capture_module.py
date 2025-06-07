import subprocess
import logging
import time
import os
from . import config
from .core.network_utils import interface_exists, is_monitor_mode # Import for interface checks
from .core.event_logger import log_event # For consistency, though not explicitly requested for this module's events yet

logger = logging.getLogger(__name__)

class HandshakeCapture:
    def __init__(self, iface, ssid=None, bssid=None, channel=None,
                 output_dir=None, file_prefix=None): # Allow overriding config via params
        self.iface = iface
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel

        # Use config values if parameters are not provided
        self.output_dir = output_dir if output_dir is not None else config.HANDSHAKE_CAPTURE_DIR
        effective_file_prefix = file_prefix if file_prefix is not None else config.HANDSHAKE_CAPTURE_PREFIX

        self.process = None
        # Ensure output directory exists (relative to project root)

        # Generate a unique filename for this capture session
        # Using a more descriptive name if SSID or BSSID is known
        target_name_part = "any_target"
        if self.bssid:
            target_name_part = self.bssid.replace(":", "")
        elif self.ssid:
            target_name_part = self.ssid.replace(' ','_')

        self.filename_base = f"{effective_file_prefix}_{target_name_part}_{time.strftime('%Y%m%d%H%M%S')}"
        self.cap_file_path = os.path.join(self.output_dir, f"{self.filename_base}.cap")
        # Ensure output directory exists (relative to project root)
        os.makedirs(self.output_dir, exist_ok=True)

        # Generate a unique filename for this capture session
        # Using a more descriptive name if SSID or BSSID is known
        target_name_part = "any_target"
        if self.bssid:
            target_name_part = self.bssid.replace(":", "")
        elif self.ssid:
            target_name_part = self.ssid.replace(' ','_')

        self.filename_base = f"{effective_file_prefix}_{target_name_part}_{time.strftime('%Y%m%d%H%M%S')}"
        self.cap_file_path = os.path.join(self.output_dir, f"{self.filename_base}.cap")


    def capture(self, timeout=120): # Default timeout 2 minutes
        # Ensure interface is in monitor mode (this should ideally be handled by a separate function/endpoint)
        # For now, we assume it is, or airodump-ng will fail.

        logger.info(f"Starting handshake capture on {self.iface} for SSID: {self.ssid}, BSSID: {self.bssid}, Channel: {self.channel}")

        cmd = [
            "airodump-ng",
            self.iface,
            "--write", os.path.join(self.output_dir, self.filename_base),
            "--output-format", "pcap,csv"
        ]
        # Note: airodump-ng might create multiple files with the filename_base prefix (e.g., .cap, .csv, .kismet.csv)
        # self.cap_file_path refers to the specific .cap file we expect.

        if self.bssid:
            cmd.extend(["--bssid", self.bssid])
        elif self.ssid:
            cmd.extend(["--essid", self.ssid])

        if self.channel:
            cmd.extend(["--channel", str(self.channel)])

        logger.info(f"Starting handshake capture. Executing: {' '.join(cmd)}")

        if not interface_exists(self.iface):
            logger.error(f"Interface {self.iface} does not exist for handshake capture.")
            # Log event for this specific failure
            log_event("handshake_capture_failed", {"interface": self.iface, "reason": "Interface does not exist", "ssid": self.ssid, "bssid": self.bssid})
            return {"status": "error", "message": f"Interface {self.iface} does not exist.", "command": cmd}

        if not is_monitor_mode(self.iface):
            logger.warning(f"Interface {self.iface} is not in monitor mode. Handshake capture may fail.")
            # Log event for this warning, but proceed.
            log_event("handshake_capture_warning_monitor_mode", {"interface": self.iface, "reason": "Not in monitor mode", "ssid": self.ssid, "bssid": self.bssid})
            # If strict monitor mode is required:
            # return {"status": "error", "message": f"Interface {self.iface} not in monitor mode.", "command": cmd}

        # self.process is used by self.shutdown()
        # Ensure it's cleared if Popen fails or after process finishes.

        stdout_output, stderr_output = "", "" # Initialize to ensure they are always defined
        process_return_code = None # Initialize

        try:
            # Using text=True for automatic decoding. Added encoding and errors for robustness.
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True, encoding='utf-8', errors='ignore')

            logger.info(f"Airodump-ng process started (PID: {self.process.pid}). Capturing for {timeout} seconds...")

            try:
                # This is the primary way to manage a timed capture with airodump-ng
                stdout_output, stderr_output = self.process.communicate(timeout=timeout)
                process_return_code = self.process.returncode
                logger.info(f"Airodump-ng process (PID: {self.process.pid}) completed with exit code {process_return_code} (finished before timeout).")
            except subprocess.TimeoutExpired:
                logger.info(f"Capture duration of {timeout}s ended. Terminating airodump-ng process (PID: {self.process.pid}).")
                self.process.terminate()
                try:
                    # Wait for termination and collect any final output
                    stdout_output, stderr_output = self.process.communicate(timeout=15) # Increased timeout
                    process_return_code = self.process.returncode
                    logger.info(f"Airodump-ng process (PID: {self.process.pid}) terminated successfully after timeout signal (exit code {process_return_code}).")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Airodump-ng process (PID: {self.process.pid}) did not terminate gracefully after 15s post-terminate. Killing.")
                    self.process.kill()
                    try:
                        stdout_output, stderr_output = self.process.communicate(timeout=5) # Try to get output after kill
                        process_return_code = self.process.returncode
                    except Exception as e_comm_kill: # Catch errors during this final communicate
                        logger.error(f"Error communicating with killed PID {self.process.pid}: {e_comm_kill}")
                        process_return_code = self.process.poll() if self.process.poll() is not None else -99 # Arbitrary code for killed, no comms
                    logger.info(f"Airodump-ng process (PID: {self.process.pid}) killed (exit code {process_return_code}).")
                except Exception as e_comm: # Catch other errors during this secondary communicate
                    logger.error(f"Error communicating with terminated PID {self.process.pid}: {e_comm}", exc_info=True)
                    process_return_code = self.process.poll() if self.process.poll() is not None else -98 # Arbitrary code for comms error

            if stdout_output: logger.debug(f"Final airodump-ng stdout: {stdout_output.strip()}")
            if stderr_output: logger.debug(f"Final airodump-ng stderr: {stderr_output.strip()}") # airodump often uses stderr for status

            # File checking logic
            final_cap_path = self.cap_file_path
            if not os.path.exists(final_cap_path): # Check for the exact file first
                # If exact file not found, search for variants (e.g., scan-01.cap)
                found_caps = [f for f in os.listdir(self.output_dir) if f.startswith(self.filename_base) and f.endswith(".cap")]
                if found_caps:
                    final_cap_path = os.path.join(self.output_dir, sorted(found_caps)[-1]) # Get the last one if multiple parts
                    logger.info(f"Located capture file (suffixed/variant): {final_cap_path}")
                else:
                    msg = f"No capture file (e.g., {self.cap_file_path} or variants like {self.filename_base}-01.cap) found after airodump-ng execution."
                    logger.error(msg + (f" STDERR: {stderr_output.strip()}" if stderr_output else ""))
                    return {"status": "error", "message": msg, "command": cmd, "stdout": stdout_output, "stderr": stderr_output, "return_code": process_return_code}

            # At this point, final_cap_path exists.
            # A non-zero return code might be due to SIGTERM (if timed out) or other reasons.
            # If file exists, it's often considered a success or partial success.
            if process_return_code == 0:
                logger.info(f"Handshake capture process completed successfully. File: {final_cap_path}")
                return {"status": "success", "file": final_cap_path, "message": "Capture completed successfully.", "command": cmd, "stdout": stdout_output, "stderr": stderr_output, "return_code": process_return_code}
            else: # Non-zero return code but file exists
                logger.warning(f"Airodump-ng exited with code {process_return_code} but capture file {final_cap_path} was found.")
                return {"status": "success_with_errors", "file": final_cap_path, "message": f"Airodump-ng may have had issues or was terminated (code {process_return_code}), but a capture file was found. Stderr: {stderr_output.strip()}", "command": cmd, "stdout": stdout_output, "stderr": stderr_output, "return_code": process_return_code}

        except FileNotFoundError:
            logger.error(f"Command 'airodump-ng' not found. Please ensure aircrack-ng suite is installed.", exc_info=True)
            return {"status": "error", "message": "'airodump-ng' not found. Is it installed and in PATH?", "command": cmd if 'cmd' in locals() else ['airodump-ng']}
        except Exception as e:
            logger.error(f"An unexpected error occurred during handshake capture with command '{' '.join(cmd if 'cmd' in locals() else ['airodump-ng'])}'", exc_info=True)
            # Try to get Popen process details if it exists and failed mid-operation
            stdout_final, stderr_final = stdout_output, stderr_output # Use already captured output if available
            rc = process_return_code
            if self.process and self.process.poll() is None: # If process still running and exception outside communicate
                try:
                    stdout_final_exc, stderr_final_exc = self.process.communicate(timeout=1) # Short timeout
                    stdout_final = stdout_final or stdout_final_exc; stderr_final = stderr_final or stderr_final_exc
                    rc = self.process.returncode
                except: pass
            return {"status": "error", "message": f"An unexpected error occurred: {str(e)}", "command": cmd if 'cmd' in locals() else ['airodump-ng'], "stdout": stdout_final, "stderr": stderr_final, "return_code": rc}
        finally:
            self.process = None # Clear self.process once Popen object is done

    def shutdown(self):
        if self.process and self.process.poll() is None: # Check if a process was stored and is running
            logger.info(f"Shutdown called: stopping active handshake capture process (PID: {self.process.pid})...")
            self.process.terminate()
            try:
                self.process.wait(timeout=15) # Increased timeout
                logger.info(f"Handshake capture process (PID: {self.process.pid}) terminated successfully on shutdown.")
            except subprocess.TimeoutExpired:
                logger.warning(f"Handshake capture process (PID: {self.process.pid}) did not terminate gracefully on shutdown. Killing.")
                self.process.kill()
                try: self.process.wait(timeout=5) # Wait for kill
                except subprocess.TimeoutExpired: logger.error(f"Failed to get return code for killed PID {self.process.pid} during shutdown.")
                logger.info(f"Handshake capture process (PID: {self.process.pid}) killed on shutdown.")
            except Exception as e:
                 logger.error(f"Error waiting for handshake capture process {self.process.pid} to stop during shutdown: {e}", exc_info=True)
            self.process = None # Clear after handling
        else:
            logger.info("HandshakeCapture shutdown: No active capture process found.")

# Example Usage (for testing)
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    # Create a dummy interface for testing if needed:
    # os.system("sudo iw phy phy0 interface add mon0 type monitor")
    # os.system("sudo ifconfig mon0 up")

    # NOTE: You'd need a Wi-Fi card and be running as root for this to actually work.
    # And ensure 'mon0' or your actual monitor interface is up.
    capture_instance = HandshakeCapture(iface="mon0", ssid="YourTestSSID", channel=6)
    # To test BSSID capture:
    # capture_instance = HandshakeCapture(iface="mon0", bssid="XX:XX:XX:XX:XX:XX", channel=6)

    result = capture_instance.capture(timeout=30) # Capture for 30s
    print(f"Capture result: {result}")

    # Clean up dummy interface if created
    # os.system("sudo iw dev mon0 del")
    # os.system("sudo ifconfig wlan0 up") # Or whatever your original iface was
    capture_instance.shutdown() # Ensure it's stopped if an error occurred before timeout
    if result.get("file") and os.path.exists(result["file"]):
        print(f"Handshake file created: {result['file']}")
        # os.remove(result['file']) # Clean up created file
        # csv_file = result['file'].replace('.cap', '.csv') # airodump-ng might create this
        # if os.path.exists(csv_file): os.remove(csv_file)
    # Potentially other files like .csv, .kismet.csv, .kismet.netxml etc. might be created by airodump-ng
    # based on its --write prefix and output-format.
    # The HandshakeCapture class is primarily concerned with the .cap file.
    # Cleaning up other associated files could be a separate utility or handled by the user.

    # For testing, let's list what was created with the base name
    if os.path.exists(capture_instance.output_dir):
        logger.debug(f"Files in {capture_instance.output_dir} with prefix {capture_instance.filename_base}:")
        for f_name in os.listdir(capture_instance.output_dir):
            if f_name.startswith(capture_instance.filename_base):
                logger.debug(f" - {f_name}")
                # Example: os.remove(os.path.join(capture_instance.output_dir, f_name)) # to clean up

    print("Test finished.")
