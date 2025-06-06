import subprocess
import logging
import os # For __main__ example file checks
from typing import Optional, Dict, Any, List

# Attempt to import from local package structure
try:
    from . import config # For AIRCRACK_TIMEOUT
    from ..core.event_logger import log_event
except ImportError:
    # Fallback for direct execution or different environment setups
    logger = logging.getLogger(__name__)
    logger.warning("Running WifiCracker with fallback imports. Ensure 'config' and 'core.event_logger' are accessible.")
    import config # type: ignore
    from core.event_logger import log_event # type: ignore


logger = logging.getLogger(__name__)

class WifiCracker:
    """
    Manages the execution of aircrack-ng to crack Wi-Fi WPA/WPA2 PSKs
    from a handshake capture file using a wordlist.
    """

    def __init__(self,
                 handshake_file: str,
                 wordlist: str,
                 bssid: Optional[str] = None):
        """
        Initializes the WifiCracker instance.

        Args:
            handshake_file: Path to the .cap file containing the WPA/WPA2 handshake.
            wordlist: Path to the wordlist file to use for cracking.
            bssid: Optional. The BSSID (MAC address) of the target access point.
                   Providing this can significantly speed up aircrack-ng and avoid ambiguity
                   if the capture file contains multiple networks.
        """
        self.handshake_file: str = handshake_file
        self.wordlist: str = wordlist
        self.bssid: Optional[str] = bssid
        self.process: Optional[subprocess.Popen] = None

        logger.debug(f"WifiCracker initialized. Handshake: '{self.handshake_file}', Wordlist: '{self.wordlist}', BSSID: {self.bssid if self.bssid else 'Not provided'}")

    def run(self) -> Dict[str, Any]:
        """
        Executes aircrack-ng to attempt to crack the Wi-Fi password.

        Manages the aircrack-ng subprocess, including timeout handling,
        real-time output parsing for the key, and logging of significant events.

        Returns:
            A dictionary containing the outcome:
            {
                "status": "success" | "failed" | "error" | "timeout",
                "password": "found_password" (if status is "success"),
                "message": "Descriptive message of the outcome.",
                "command": ["executed", "command", "list"],
                "output": "Full stdout from aircrack-ng",
                "error_output": "Full stderr from aircrack-ng",
                "return_code": integer_exit_code_or_None
            }
        """
        cmd: List[str] = [
            "aircrack-ng",
            "-w", self.wordlist,
            # Consider adding "-l <key_file_path>" to write key to a file, though parsing stdout is common.
        ]

        if self.bssid:
            cmd.extend(["-b", self.bssid])
        else:
            # This is a critical warning. Aircrack-ng might fail, hang, or prompt if multiple APs are in the capture.
            logger.warning("BSSID not provided to WifiCracker. Aircrack-ng might fail, prompt for selection, or take longer if the capture file contains multiple networks.")
            logger.warning("It is highly recommended to provide a BSSID for reliable and targeted cracking.")
            # We proceed, but this is a common point of failure if not handled by the user/caller.

        cmd.append(self.handshake_file) # Must be the last option for aircrack-ng usually

        base_event_data = {
            "handshake_file": self.handshake_file, "wordlist": self.wordlist, "bssid": self.bssid,
            "command_line": ' '.join(cmd)
        }
        logger.info(f"Starting Wi-Fi cracking. Executing: {' '.join(cmd)}")
        log_event("wifi_crack_started", base_event_data)

        stdout_lines: List[str] = []
        found_password: Optional[str] = None

        # Get timeout from config, with a fallback default (e.g., 1 hour)
        # Ensure config is loaded; if not, provide a very basic fallback for AIRCRACK_TIMEOUT
        aircrack_timeout_seconds: int = 3600 # Default to 1 hour
        if hasattr(config, 'AIRCRACK_TIMEOUT'):
            try:
                aircrack_timeout_seconds = int(config.AIRCRACK_TIMEOUT)
                if aircrack_timeout_seconds <= 0: # Ensure positive timeout
                    logger.warning(f"Configured AIRCRACK_TIMEOUT ({config.AIRCRACK_TIMEOUT}) is not positive. Using default: 3600s.")
                    aircrack_timeout_seconds = 3600
            except ValueError:
                logger.warning(f"Configured AIRCRACK_TIMEOUT ('{config.AIRCRACK_TIMEOUT}') is not a valid integer. Using default: 3600s.")
                aircrack_timeout_seconds = 3600
        else:
            logger.warning(f"Config variable 'AIRCRACK_TIMEOUT' not found. Using default: {aircrack_timeout_seconds}s.")

        logger.info(f"Aircrack-ng process timeout set to {aircrack_timeout_seconds} seconds.")
        base_event_data["timeout_configured"] = aircrack_timeout_seconds


        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, # Decode output as text
                bufsize=1, # Line buffered
                universal_newlines=True # Ensure consistent newline handling
            )
            pid = self.process.pid
            logger.info(f"Aircrack-ng process (PID: {pid}) started.")
            base_event_data["pid"] = pid

            # Real-time processing of stdout to find the key
            if self.process.stdout:
                for line in iter(self.process.stdout.readline, ''):
                    line_stripped = line.strip()
                    logger.debug(f"Aircrack-ng (PID {pid}) stdout: {line_stripped}")
                    stdout_lines.append(line) # Store original line with newline
                    if "KEY FOUND!" in line_stripped:
                        # Expected format: "KEY FOUND! [ <password> ]"
                        parts = line_stripped.split('[')
                        if len(parts) > 1:
                            password_candidate = parts[-1].split(']')[0].strip()
                            if password_candidate: # Ensure it's not empty
                                found_password = password_candidate
                                logger.info(f"Password found by aircrack-ng (PID {pid}): '{found_password}'")
                                log_event("wifi_crack_key_found_realtime", {**base_event_data, "password": found_password})
                                logger.info(f"Terminating aircrack-ng (PID {pid}) early as key was found.")
                                self.process.terminate() # Send SIGTERM
                                break # Exit loop once key is found
                self.process.stdout.close() # Close stdout pipe

            # Wait for the process to complete, with a timeout
            final_wait_timeout = 15 if found_password else aircrack_timeout_seconds # Shorter wait if already terminated
            try:
                self.process.wait(timeout=final_wait_timeout)
            except subprocess.TimeoutExpired:
                logger.warning(f"Aircrack-ng process (PID: {pid}) timed out after {final_wait_timeout}s. Killing.")
                log_event("wifi_crack_timeout", {**base_event_data, "timeout_duration": final_wait_timeout})
                self.process.kill() # Force kill
                try:
                    self.process.wait(timeout=10) # Wait for kill to complete
                except subprocess.TimeoutExpired:
                    logger.error(f"Failed to get return code for PID {pid} after kill signal.")

                # Collect any remaining output after timeout/kill (best effort)
                stderr_str_timeout = ""
                if self.process.stderr:
                    try: stderr_str_timeout = self.process.stderr.read()
                    except Exception: pass # pylint: disable=broad-except
                    self.process.stderr.close()

                full_stdout_str_timeout = "".join(stdout_lines)
                logger.error(f"Aircrack-ng command '{' '.join(cmd)}' timed out. Partial stdout: {full_stdout_str_timeout.strip()}")
                return {"status": "timeout", "message": "Cracking process timed out.", "command": cmd, "output": full_stdout_str_timeout, "error_output": stderr_str_timeout, "return_code": self.process.returncode}

            return_code = self.process.returncode
            stderr_str = ""
            if self.process.stderr: # Ensure stderr pipe is also closed
                stderr_str = self.process.stderr.read()
                self.process.stderr.close()

            full_stdout_str = "".join(stdout_lines)

            if found_password: # Password found during real-time parse
                 logger.info(f"WifiCracker returning success (password found real-time): '{found_password}'")
                 # Event already logged when found, but can log completion
                 log_event("wifi_crack_success", {**base_event_data, "password": found_password, "return_code": return_code, "source": "realtime_parse"})
                 return {"status": "success", "password": found_password, "command": cmd, "output": full_stdout_str, "error_output": stderr_str, "return_code": return_code}

            # If process finished naturally (return_code 0 or other) but no password found yet, check full output again.
            # This is a fallback, as real-time parsing should catch it.
            if "KEY FOUND!" in full_stdout_str:
                key_found_line_fallback = next((l for l in stdout_lines if "KEY FOUND!" in l), None)
                if key_found_line_fallback:
                    parts_fallback = key_found_line_fallback.strip().split('[')
                    if len(parts_fallback) > 1:
                        password_fallback = parts_fallback[-1].split(']')[0].strip()
                        if password_fallback:
                            found_password = password_fallback
                            logger.info(f"Password found in final full stdout check: '{found_password}' (PID {pid})")
                            log_event("wifi_crack_success", {**base_event_data, "password": found_password, "return_code": return_code, "source": "final_parse"})
                            return {"status": "success", "password": found_password, "command": cmd, "output": full_stdout_str, "error_output": stderr_str, "return_code": return_code}

            # If no password found after all checks
            msg = "Password not found by aircrack-ng."
            logger.info(f"Aircrack-ng (PID {pid}) finished. {msg} RC: {return_code}.")
            log_event("wifi_crack_failed_no_key", {**base_event_data, "reason": msg, "return_code": return_code, "stdout_snippet": full_stdout_str[-200:]}) # Log last part of stdout
            return {"status": "failed", "message": msg, "output": full_stdout_str, "error_output": stderr_str, "command": cmd, "return_code": return_code}

        except FileNotFoundError:
            msg = f"Command 'aircrack-ng' not found. Please ensure aircrack-ng suite is installed and in PATH."
            logger.error(msg, exc_info=True)
            log_event("wifi_crack_failed_tool_not_found", base_event_data)
            return {"status": "error", "message": msg, "command": cmd}
        except Exception as e:
            msg = f"An unexpected error occurred during Wi-Fi cracking: {str(e)}"
            logger.error(msg + f" Command: '{' '.join(cmd)}'", exc_info=True)
            log_event("wifi_crack_failed_unexpected_exception", {**base_event_data, "exception_type": type(e).__name__, "error_details": str(e)})
            return {"status": "error", "message": msg, "command": cmd}
        finally:
            if self.process and self.process.poll() is None:
                pid = self.process.pid
                logger.warning(f"Aircrack-ng process (PID {pid}) still running in `finally` block. Attempting to terminate.")
                self.process.terminate()
                try: self.process.wait(timeout=5)
                except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=5)
                except Exception: pass # Best effort
            self.process = None


    def shutdown(self) -> None:
        """
        Stops an active aircrack-ng process, if one is running.
        Sends SIGTERM, then SIGKILL if necessary.
        """
        if self.process and self.process.poll() is None: # Check if Popen object exists and process is running
            pid = self.process.pid
            logger.info(f"Shutdown called: stopping active Wi-Fi cracking process (PID: {pid})...")
            log_event("wifi_crack_shutdown_initiated", {"pid": pid, "handshake_file": self.handshake_file})
            self.process.terminate() # Send SIGTERM
            try:
                self.process.wait(timeout=10) # Wait for graceful termination
                logger.info(f"Wi-Fi cracking process (PID: {pid}) terminated successfully on shutdown (exit code {self.process.returncode}).")
                log_event("wifi_crack_shutdown_complete", {"pid": pid, "exit_code": self.process.returncode, "method": "terminate"})
            except subprocess.TimeoutExpired:
                logger.warning(f"Wi-Fi cracking process (PID: {pid}) did not terminate gracefully after 10s. Killing.")
                self.process.kill() # Force kill
                try:
                    self.process.wait(timeout=5)
                    logger.info(f"Wi-Fi cracking process (PID: {pid}) killed on shutdown (exit code {self.process.returncode}).")
                    log_event("wifi_crack_shutdown_complete", {"pid": pid, "exit_code": self.process.returncode, "method": "kill"})
                except subprocess.TimeoutExpired:
                     logger.error(f"Failed to get return code for killed PID {pid} during shutdown.")
                     log_event("wifi_crack_shutdown_failed", {"pid": pid, "reason": "Failed to get exit code after kill"})
                except Exception as e_kill_wait: # pylint: disable=broad-except
                     logger.error(f"Error waiting for killed PID {pid} to exit: {e_kill_wait}", exc_info=True)
            except Exception as e_term_wait: # pylint: disable=broad-except
                 logger.error(f"Error waiting for terminated PID {pid} to exit: {e_term_wait}", exc_info=True)

            self.process = None # Clear process attribute
        else:
            logger.info("WifiCracker shutdown: No active cracking process found or process already terminated.")

# Example Usage (for testing this module directly)
if __name__ == '__main__':
    import sys # For sys.stdout, sys.exit
    # Ensure os is available if not already imported globally
    # import os # Imported globally

    # --- Test Setup ---
    logging.basicConfig(
        level=logging.DEBUG, # Set to INFO for less verbosity
        format="%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d %(funcName)s): %(message)s",
        stream=sys.stdout
    )
    logger.info("--- Starting Wi-Fi Cracker Module Test ---")

    # --- IMPORTANT: Test Prerequisites ---
    # 1. Aircrack-ng Suite: Ensure `aircrack-ng` is installed and in your system's PATH.
    # 2. Sample Handshake File: You need a .cap file containing a WPA/WPA2 handshake.
    #    - You can capture one using tools like `airodump-ng`.
    #    - For testing a successful crack, this file should contain a handshake for which
    #      you know the password, and that password should be in your test wordlist.
    # 3. Sample Wordlist: A text file with one password candidate per line.
    # ---

    # ** MODIFY THESE VALUES FOR YOUR TEST ENVIRONMENT **
    # Provide paths to your actual test files.
    test_handshake_file = "test_handshake.cap"  # Replace with path to your .cap file
    test_wordlist_file = "test_wordlist.txt"    # Replace with path to your wordlist
    # Optional: Provide BSSID if known and relevant for your test .cap file
    test_bssid_optional: Optional[str] = "AA:BB:CC:DD:EE:FF" # Example BSSID, replace or set to None

    # --- Pre-run Checks for Test Files ---
    logger.info(f"--- Pre-run File Checks ---")
    if not os.path.exists(test_handshake_file):
        logger.critical(f"CRITICAL TEST SETUP ERROR: Handshake file not found: '{test_handshake_file}'")
        logger.critical("Please create this file or update 'test_handshake_file' variable in the script.")
        # Create a dummy file for demonstration if it's missing, so the script can run further for structure check.
        # In a real test, you'd likely sys.exit(1)
        if not os.path.exists(test_handshake_file):
            logger.warning(f"Attempting to create a dummy empty handshake file for test run: {test_handshake_file}")
            try: open(test_handshake_file, 'a').close()
            except OSError as e: logger.error(f"Could not create dummy handshake file: {e}")
        # sys.exit(1) # Uncomment if strict file existence is required to proceed

    if not os.path.exists(test_wordlist_file):
        logger.critical(f"CRITICAL TEST SETUP ERROR: Wordlist file not found: '{test_wordlist_file}'")
        logger.critical("Please create this file or update 'test_wordlist_file' variable in the script.")
        # Create a dummy wordlist
        if not os.path.exists(test_wordlist_file):
            logger.warning(f"Attempting to create a dummy wordlist for test run: {test_wordlist_file}")
            try:
                with open(test_wordlist_file, 'w', encoding='utf-8') as f:
                    f.write("password123\n")
                    f.write("testpassword\n")
            except OSError as e: logger.error(f"Could not create dummy wordlist: {e}")
        # sys.exit(1) # Uncomment if strict file existence is required


    # --- Test Execution ---
    logger.info(f"\n--- Initializing WifiCracker ---")
    logger.info(f"Using Handshake File: '{test_handshake_file}'")
    logger.info(f"Using Wordlist: '{test_wordlist_file}'")
    if test_bssid_optional:
        logger.info(f"Using BSSID: '{test_bssid_optional}'")
    else:
        logger.info("BSSID: Not provided (module will log a warning).")

    cracker_instance = WifiCracker(
        handshake_file=test_handshake_file,
        wordlist=test_wordlist_file,
        bssid=test_bssid_optional
    )

    logger.info(f"\n--- Starting Cracking Process ---")
    crack_result: Dict[str, Any] = {}
    try:
        crack_result = cracker_instance.run()
    except Exception as e_run: # Catch exceptions from the run() call itself
        logger.error(f"An unexpected exception occurred directly from cracker_instance.run(): {e_run}", exc_info=True)
        crack_result = {"status": "exception_in_test_harness_run", "message": str(e_run)}
    finally:
        logger.info("Executing `finally` block: Calling shutdown() on WifiCracker instance...")
        cracker_instance.shutdown() # Ensure aircrack-ng is stopped if it was running

    # --- Test Results ---
    logger.info(f"\n--- Cracking Process Summary ---")
    logger.info(f"Status: {crack_result.get('status')}")
    if crack_result.get('status') == 'success':
        logger.info(f"Password Found: '{crack_result.get('password')}'")
    else:
        logger.info(f"Message: {crack_result.get('message')}")

    logger.debug(f"Full command executed: {crack_result.get('command')}")
    # Optionally print snippets of stdout/stderr if they are very long
    # logger.debug(f"Aircrack stdout: {crack_result.get('output', '')[:500]}...")
    # logger.debug(f"Aircrack stderr: {crack_result.get('error_output', '')[:500]}...")


    # --- Cleanup (Optional) ---
    # If you created dummy files for testing, you might want to remove them.
    # For this example, manual cleanup of test_handshake.cap and test_wordlist.txt is assumed.
    # if test_handshake_file == "test_handshake.cap" and os.path.exists(test_handshake_file):
    #     os.remove(test_handshake_file)
    #     logger.info(f"Removed dummy handshake file: {test_handshake_file}")
    # if test_wordlist_file == "test_wordlist.txt" and os.path.exists(test_wordlist_file):
    #     os.remove(test_wordlist_file)
    #     logger.info(f"Removed dummy wordlist file: {test_wordlist_file}")

    logger.info("\n--- Wi-Fi Cracker Module Test Finished ---")
    logger.info("Review logs above for detailed outcomes, especially if aircrack-ng reported errors or no key was found.")
