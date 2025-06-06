#!/usr/bin/env python3
"""
Cracks a WPA/WPA2 handshake file using aircrack-ng and a wordlist.

This module attempts to find the passphrase for a captured handshake file
(.cap, .pcap) by trying passwords from a given wordlist.

Required System Dependencies:
- aircrack-ng

Usage (as script):
    python3 handshake.py <handshake.cap> <wordlist.txt> [--timeout <seconds>]
"""
import subprocess
import json
import argparse
import re
from datetime import datetime
from typing import Optional, Dict, Any

def run_cracking_tool(
    handshake_path: str,
    wordlist_path: str,
    timeout_duration: Optional[int] = 3600  # Default 1 hour
) -> str:
    """
    Attempts to crack a handshake file using aircrack-ng.

    Args:
        handshake_path: Path to the handshake capture file (.cap, .pcap).
        wordlist_path: Path to the wordlist file.
        timeout_duration: Optional timeout in seconds for aircrack-ng.
                          If None, no timeout is applied.

    Returns:
        A JSON string detailing the outcome, including whether the password
        was found, and any output or errors from aircrack-ng.
    """
    command = ["aircrack-ng", "-w", wordlist_path, "-l", "/dev/null", handshake_path] # -l /dev/null to avoid writing .crack file
    # Alternative: aircrack-ng -w wordlist_path -b <bssid_if_known> handshake_path
    # BSSID can sometimes speed things up if multiple handshakes are in the file.
    # For simplicity, not requiring BSSID here.

    timestamp = datetime.now().isoformat()
    json_result: Dict[str, Any] = {
        "timestamp": timestamp,
        "command": command,
        "status": "error", # Default to error
        "password_found": None,
        "password": None,
        "output": "",
        "errors": ""
    }

    try:
        print(json.dumps({ # Initial status for CLI use
            "timestamp": timestamp,
            "status": "running",
            "message": f"Starting crack with '{wordlist_path}' on '{handshake_path}'",
            "command": command
        }))

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False, # aircrack-ng might exit 0 even if key not found
            timeout=timeout_duration
        )

        json_result["output"] = result.stdout.strip()
        json_result["errors"] = result.stderr.strip()

        # Parse aircrack-ng output for key
        key_found_match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result.stdout, re.IGNORECASE)

        if key_found_match:
            json_result["status"] = "success"
            json_result["password_found"] = True
            json_result["password"] = key_found_match.group(1).strip()
            json_result["message"] = "Password successfully found."
        elif "Passphrase not in dictionary" in result.stdout or "No keys found" in result.stdout or "0 keys tested" in result.stdout :
             # Check common phrases indicating wordlist exhaustion without success
            json_result["status"] = "success" # Tool ran successfully
            json_result["password_found"] = False
            json_result["message"] = "Password not found in the provided wordlist."
        elif result.returncode != 0:
            json_result["status"] = "error"
            json_result["message"] = f"aircrack-ng exited with error code {result.returncode}."
            # Errors might already be in json_result["errors"] from stderr
        else:
            # Unknown state, aircrack-ng exited 0 but no clear success/failure message found
            # This case might need refinement based on more aircrack-ng output variants
            json_result["status"] = "success" # Assume tool ran
            json_result["password_found"] = False
            json_result["message"] = "Cracking process completed. Key status undetermined from output (no clear 'KEY FOUND' or 'not in dictionary' message)."


    except subprocess.TimeoutExpired as e:
        json_result["message"] = f"aircrack-ng command timed out after {timeout_duration or 'infinite'} seconds."
        json_result["output"] = e.stdout.decode(errors='ignore').strip() if e.stdout else ""
        json_result["errors"] = e.stderr.decode(errors='ignore').strip() if e.stderr else "No stderr output on timeout."
    except FileNotFoundError:
        json_result["message"] = "aircrack-ng command not found. Is aircrack-ng installed and in PATH?"
        json_result["errors"] = "Command not found."
    except Exception as e:
        json_result["message"] = f"An unexpected error occurred: {str(e)}"
        json_result["errors"] = str(e)

    return json.dumps(json_result, indent=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Crack WPA/WPA2 handshake using aircrack-ng and a wordlist.",
        epilog="Example: python3 handshake.py myhandshake.cap wordlist.txt --timeout 600"
    )
    parser.add_argument(
        "handshake_path",
        help="Path to the handshake capture file (e.g., myhandshake.cap)."
    )
    parser.add_argument(
        "wordlist_path",
        help="Path to the wordlist file (e.g., rockyou.txt)."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3600, # Default to 1 hour for CLI
        help="Optional timeout in seconds for aircrack-ng (default: 3600). Use 0 for no timeout."
    )

    args = parser.parse_args()

    timeout_val = args.timeout if args.timeout > 0 else None

    result = run_cracking_tool(
        handshake_path=args.handshake_path,
        wordlist_path=args.wordlist_path,
        timeout_duration=timeout_val
    )
    print(result)

    try:
        result_data = json.loads(result)
        if result_data.get("status") != "success" or not result_data.get("password_found"):
            # Optional: exit with non-zero status if password not found or error occurred
            # sys.exit(1)
            pass
    except json.JSONDecodeError:
        # sys.exit(1)
        pass
