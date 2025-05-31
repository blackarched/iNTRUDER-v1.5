import subprocess
import logging

logger = logging.getLogger(__name__) # This will inherit root logger's config

class WifiCracker:
    def __init__(self, handshake_file, wordlist):
        self.handshake_file = handshake_file
        self.wordlist = wordlist
        self.process = None

    def run(self):
        cmd = [
            "aircrack-ng",
            "-w", self.wordlist,
            self.handshake_file
        ]
        # Note: aircrack-ng might require a BSSID to be specified with -b <bssid> if multiple networks are in the .cap
        # For now, we're omitting it, relying on user providing a clean .cap or aircrack-ng's behavior for single-network files.
        logger.info(f"Starting Wi-Fi cracking for {self.handshake_file} with wordlist {self.wordlist}. Executing: {' '.join(cmd)}")

        # The original handshake.py used to call:
        # The original handshake.py used to call:
        # process = subprocess.Popen(['aircrack-ng', '-w', wordlist_path, '-b', bssid, cap_file_path_cap], ...)
        # The server endpoint for /api/crack/start currently only takes handshake_file and wordlist.
        # This will need to be addressed either by:
        # 1. Modifying the server to also accept BSSID.
        # 2. Attempting to extract BSSID from the .cap file (if that's even reliably possible for aircrack-ng).
        # 3. Forcing the user to rename the .cap file to <ESSID>.cap or <BSSID>.cap and parse it.
        # For now, I'll proceed without the BSSID, which might make aircrack-ng prompt or fail.
        # The API contract might need adjustment in a later step.

        try:
            # Using Popen for potentially long-running process
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)

            stdout_lines = []
            password = None

            # Define a timeout for the cracking process (e.g., 1 hour = 3600 seconds)
            # This should ideally be configurable. For now, a long default.
            crack_timeout = getattr(config, 'AIRCRACK_TIMEOUT', 3600)
            logger.info(f"Aircrack-ng process timeout set to {crack_timeout} seconds.")

            # Real-time processing of stdout to find the key
            for line in iter(self.process.stdout.readline, ''):
                logger.debug(f"Aircrack-ng output: {line.strip()}")
                stdout_lines.append(line)
                if "KEY FOUND!" in line:
                    password_candidate = line.split('[')[-1].split(']')[0].strip()
                    if password_candidate:
                        password = password_candidate
                        logger.info(f"Password found by aircrack-ng: {password}")
                        # Terminate aircrack-ng early as key is found
                        logger.info("Terminating aircrack-ng early as key was found.")
                        self.process.terminate()
                        break

            # Ensure stdout pipe is closed before waiting or reading stderr fully
            if self.process.stdout:
                self.process.stdout.close()

            # Wait for the process to complete, with a timeout
            try:
                # If terminate() was called above, wait() should return quickly.
                # If loop finished without finding key, wait() will wait for aircrack-ng to finish or timeout.
                self.process.wait(timeout=crack_timeout if not password else 15) # Shorter timeout if already terminated
            except subprocess.TimeoutExpired:
                logger.warning(f"Aircrack-ng process (PID: {self.process.pid}) timed out after {crack_timeout}s. Terminating.")
                self.process.kill() # Force kill if wait times out
                # Wait a moment for kill to process
                try: self.process.wait(timeout=10)
                except subprocess.TimeoutExpired: logger.error(f"Failed to collect return code for PID {self.process.pid} after kill.")

                # After kill, stderr might not be readable or complete.
                stderr_output_on_timeout = ""
                if self.process.stderr:
                    try: stderr_output_on_timeout = self.process.stderr.read()
                    except: pass # Ignore errors reading stderr from killed process
                    self.process.stderr.close()

                full_stdout_on_timeout = ''.join(stdout_lines)
                logger.error(f"Aircrack-ng command '{' '.join(cmd)}' timed out. Partial stdout: {full_stdout_on_timeout}")
                return {"status": "error", "message": "Cracking process timed out.", "command": cmd, "output": full_stdout_on_timeout, "error_output": stderr_output_on_timeout}

            # Get final return code and stderr
            return_code = self.process.returncode
            stderr_output = ""
            if self.process.stderr: # Ensure stderr pipe is also closed
                stderr_output = self.process.stderr.read()
                self.process.stderr.close()

            full_stdout = ''.join(stdout_lines)

            if password: # If password was found (and process terminated early)
                 logger.info(f"WifiCracker returning success, password found: {password}")
                 return {"status": "success", "password": password, "command": cmd, "output": full_stdout, "error_output": stderr_output, "return_code": return_code}

            if return_code == 0: # Process finished naturally, but no password found in loop
                logger.info(f"Aircrack-ng completed (code {return_code}). No key found during real-time parse. Full stdout: {full_stdout}")
                # Check full output again just in case (though unlikely if not caught by line iteration)
                key_found_line = next((l for l in stdout_lines if "KEY FOUND!" in l), None)
                if key_found_line:
                    password = key_found_line.split('[')[-1].split(']')[0].strip()
                    if password:
                        logger.info(f"Password found in final full stdout check: {password}")
                        return {"status": "success", "password": password, "command": cmd, "output": full_stdout, "error_output": stderr_output, "return_code": return_code}

                logger.info("Aircrack-ng finished, password not found.")
                return {"status": "failed", "message": "Password not found by aircrack-ng.", "output": full_stdout, "error_output": stderr_output, "command": cmd, "return_code": return_code}
            else: # Non-zero return code indicates an error (or early termination by finding password, handled above)
                logger.error(f"Aircrack-ng command '{' '.join(cmd)}' finished with code {return_code}. stderr: {stderr_output}, stdout: {full_stdout}", exc_info=True)
                return {"status": "error", "message": stderr_output.strip() or "Aircrack-ng failed. Check logs.", "output": full_stdout, "error_output": stderr_output, "command": cmd, "return_code": return_code}

        except FileNotFoundError: # For Popen itself
            logger.error(f"Command 'aircrack-ng' not found. Please ensure aircrack-ng suite is installed.", exc_info=True)
            return {"status": "error", "message": "'aircrack-ng' not found. Is it installed and in PATH?", "command": cmd}
        except Exception as e: # Catch-all for other Popen issues or logic errors
            logger.error(f"An unexpected error occurred during Wi-Fi cracking with command '{' '.join(cmd)}'", exc_info=True)
            return {"status": "error", "message": f"An unexpected error occurred: {str(e)}", "command": cmd}

    def shutdown(self):
        if self.process and self.process.poll() is None: # Check if process is running
            logger.info("Stopping Wi-Fi cracking process...")
            self.process.terminate()
            try:
                self.process.wait(timeout=10) # Wait for graceful termination
            except subprocess.TimeoutExpired:
                self.process.kill() # Force kill if terminate doesn't work
                logger.warning("Wi-Fi cracking process force-killed.")
            logger.info("Wi-Fi cracking process stopped.")
        else:
            logger.info("Wi-Fi cracking process not running or already stopped.")
