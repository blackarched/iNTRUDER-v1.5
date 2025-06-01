import subprocess
import logging
import time
import os
from .. import config
from ..core.network_utils import interface_exists, is_monitor_mode # Import for interface checks
from ..core.event_logger import log_event # For consistency, though not explicitly requested for this module's events yet

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

        logger.info(f"Starting handshake capture on {self.iface} for SSID: {self.ssid}, BSSID: {self.bssid}, Channel: {self.channel} using sudo and wrapper script.")

        # Base command for the wrapper script
        script_path = os.path.join(config.WRAPPER_SCRIPT_DIR, 'run_airodump_capture.sh')
        cmd_base = [
            config.SUDO_COMMAND, script_path,
            self.iface, # Interface passed to script
            "--write", os.path.join(self.output_dir, self.filename_base), # Full path for --write
            "--output-format", "pcap,csv" # Let airodump-ng handle formats
        ]

        # Append specific targeting options
        if self.bssid:
            cmd_base.extend(["--bssid", self.bssid])
        elif self.ssid: # Only use ESSID if BSSID is not specified, as BSSID is more specific
            cmd_base.extend(["--essid", self.ssid])

        if self.channel:
            cmd_base.extend(["--channel", str(self.channel)])

        final_cmd = cmd_base
        logger.info(f"Starting handshake capture via wrapper script. Executing: {' '.join(final_cmd)}")

        if not interface_exists(self.iface):
            logger.error(f"Interface {self.iface} does not exist for handshake capture.")
            log_event("handshake_capture_failed", {"interface": self.iface, "reason": "Interface does not exist", "ssid": self.ssid, "bssid": self.bssid})
            return {"status": "error", "message": f"Interface {self.iface} does not exist.", "command": final_cmd}

        if not is_monitor_mode(self.iface):
            logger.warning(f"Interface {self.iface} is not in monitor mode. Handshake capture may fail.")
            log_event("handshake_capture_warning_monitor_mode", {"interface": self.iface, "reason": "Not in monitor mode", "ssid": self.ssid, "bssid": self.bssid})

        stdout_output, stderr_output = "", ""
        process_return_code = None

        try:
            self.process = subprocess.Popen(final_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True, encoding='utf-8', errors='ignore')
            logger.info(f"run_airodump_capture.sh process started (PID: {self.process.pid}). Capturing for {timeout} seconds...")

            try:
                stdout_output, stderr_output = self.process.communicate(timeout=timeout)
                process_return_code = self.process.returncode
                logger.info(f"run_airodump_capture.sh process (PID: {self.process.pid}) completed with exit code {process_return_code} (finished before timeout).")
            except subprocess.TimeoutExpired:
                logger.info(f"Capture duration of {timeout}s ended. Terminating run_airodump_capture.sh process (PID: {self.process.pid}).")
                self.process.terminate() # SIGTERM to sudo, script should handle
                try:
                    stdout_output, stderr_output = self.process.communicate(timeout=20) # Increased timeout for script + airodump
                    process_return_code = self.process.returncode
                    logger.info(f"run_airodump_capture.sh process (PID: {self.process.pid}) terminated successfully after timeout signal (exit code {process_return_code}).")
                except subprocess.TimeoutExpired:
                    logger.warning(f"run_airodump_capture.sh process (PID: {self.process.pid}) did not terminate gracefully after 20s post-terminate. Killing.")
                    self.process.kill() # SIGKILL to sudo
                    try:
                        stdout_output, stderr_output = self.process.communicate(timeout=10)
                        process_return_code = self.process.returncode
                    except Exception as e_comm_kill:
                        logger.error(f"Error communicating with killed PID {self.process.pid}: {e_comm_kill}")
                        process_return_code = self.process.poll() if self.process.poll() is not None else -99
                    logger.info(f"run_airodump_capture.sh process (PID: {self.process.pid}) killed (exit code {process_return_code}).")
                except Exception as e_comm:
                    logger.error(f"Error communicating with terminated PID {self.process.pid}: {e_comm}", exc_info=True)
                    process_return_code = self.process.poll() if self.process.poll() is not None else -98

            if stdout_output: logger.debug(f"Final run_airodump_capture.sh stdout: {stdout_output.strip()}")
            if stderr_output: logger.debug(f"Final run_airodump_capture.sh stderr: {stderr_output.strip()}")

            final_cap_path = self.cap_file_path
            if not os.path.exists(final_cap_path):
                found_caps = [f for f in os.listdir(self.output_dir) if f.startswith(self.filename_base) and f.endswith(".cap")]
                if found_caps:
                    final_cap_path = os.path.join(self.output_dir, sorted(found_caps)[-1])
                    logger.info(f"Located capture file (suffixed/variant): {final_cap_path}")
                else:
                    msg = f"No capture file (e.g., {self.cap_file_path} or variants) found after run_airodump_capture.sh execution."
                    logger.error(msg + (f" STDERR from script: {stderr_output.strip()}" if stderr_output else ""))
                    return {"status": "error", "message": msg, "command": final_cmd, "stdout": stdout_output, "stderr": stderr_output, "return_code": process_return_code}

            if process_return_code == 0:
                logger.info(f"Handshake capture (via script) process completed successfully. File: {final_cap_path}")
                return {"status": "success", "file": final_cap_path, "message": "Capture completed successfully via script.", "command": final_cmd, "stdout": stdout_output, "stderr": stderr_output, "return_code": process_return_code}
            else:
                logger.warning(f"run_airodump_capture.sh exited with code {process_return_code} but capture file {final_cap_path} was found.")
                return {"status": "success_with_errors", "file": final_cap_path, "message": f"run_airodump_capture.sh may have had issues or was terminated (code {process_return_code}), but a capture file was found. Stderr: {stderr_output.strip()}", "command": final_cmd, "stdout": stdout_output, "stderr": stderr_output, "return_code": process_return_code}

        except FileNotFoundError:
            actual_cmd_not_found = final_cmd[0]
            if final_cmd[0] == config.SUDO_COMMAND and not os.path.exists(final_cmd[1]): # Check script path if sudo was the command
                 actual_cmd_not_found = final_cmd[1]
            elif final_cmd[0] != config.SUDO_COMMAND and not os.path.exists(final_cmd[0]): # Check command itself if not sudo
                 actual_cmd_not_found = final_cmd[0]

            logger.error(f"Command '{actual_cmd_not_found}' not found. Ensure sudo is installed and WRAPPER_SCRIPT_DIR is correct.", exc_info=True)
            return {"status": "error", "message": f"Command '{actual_cmd_not_found}' not found.", "command": final_cmd}
        except Exception as e:
            logger.error(f"An unexpected error occurred during handshake capture (via script) with command '{' '.join(final_cmd)}'", exc_info=True)
            stdout_final, stderr_final = stdout_output, stderr_output
            rc = process_return_code
            if self.process and self.process.poll() is None:
                try:
                    stdout_final_exc, stderr_final_exc = self.process.communicate(timeout=1)
                    stdout_final = stdout_final or stdout_final_exc; stderr_final = stderr_final or stderr_final_exc
                    rc = self.process.returncode
                except: pass
            return {"status": "error", "message": f"An unexpected error occurred: {str(e)}", "command": final_cmd, "stdout": stdout_final, "stderr": stderr_final, "return_code": rc}
        finally:
            self.process = None

    def shutdown(self):
        if self.process and self.process.poll() is None:
            logger.info(f"Shutdown called: stopping active handshake capture process (PID: {self.process.pid}, script run_airodump_capture.sh)...")
            self.process.terminate() # SIGTERM to sudo
            try:
                self.process.wait(timeout=20) # Increased timeout for script + airodump
                logger.info(f"Handshake capture script process (PID: {self.process.pid}) terminated successfully on shutdown.")
            except subprocess.TimeoutExpired:
                logger.warning(f"Handshake capture script process (PID: {self.process.pid}) did not terminate gracefully on shutdown. Killing.")
                self.process.kill() # SIGKILL to sudo
                try: self.process.wait(timeout=10)
                except subprocess.TimeoutExpired: logger.error(f"Failed to get return code for killed PID {self.process.pid} during shutdown.")
                logger.info(f"Handshake capture script process (PID: {self.process.pid}) killed on shutdown.")
            except Exception as e:
                 logger.error(f"Error waiting for handshake capture script process {self.process.pid} to stop during shutdown: {e}", exc_info=True)
            self.process = None
        else:
            logger.info("HandshakeCapture shutdown: No active capture script process found.")

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
