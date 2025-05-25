#!/usr/bin/env python3
import subprocess
import json
import sys
from datetime import datetime

def sniff_logs(interface="wlan0mon"):
    try:
        result = subprocess.run(
            ["sudo", "tcpdump", "-i", interface, "-vv", "-l"],
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
    interface = sys.argv[1] if len(sys.argv) > 1 else "wlan0mon"
    print(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "status": "starting",
        "message": f"Starting log sniffer on interface {interface}..."
    }))
    result = sniff_logs(interface)
    print(result)