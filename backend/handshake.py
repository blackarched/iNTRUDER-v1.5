#!/usr/bin/env python3
import subprocess
import json
import sys
from datetime import datetime

def run_cracking_tool(handshake_path, wordlist_path):
    try:
        print(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "status": "running",
            "message": f"Starting crack with {wordlist_path} on {handshake_path}"
        }))

        result = subprocess.run(
            ["aircrack-ng", "-w", wordlist_path, handshake_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        output = result.stdout
        error = result.stderr

        if result.returncode == 0:
            return json.dumps({
                "timestamp": datetime.now().isoformat(),
                "status": "success",
                "message": output
            })
        else:
            return json.dumps({
                "timestamp": datetime.now().isoformat(),
                "status": "error",
                "message": error
            })

    except Exception as e:
        return json.dumps({
            "timestamp": datetime.now().isoformat(),
            "status": "exception",
            "message": str(e)
        })

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "message": "Usage: wifi_cracker.py <handshake.cap> <wordlist.txt>"
        }))
        sys.exit(1)

    handshake_file = sys.argv[1]
    wordlist_file = sys.argv[2]
    result = run_cracking_tool(handshake_file, wordlist_file)
    print(result)