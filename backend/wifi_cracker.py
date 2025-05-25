from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

def run_command(command, shell=False):
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True)
        return {
            "status": "success" if result.returncode == 0 else "error",
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.route("/api/start-monitor", methods=["POST"])
def start_monitor():
    return jsonify(run_command(["bash", "./start-mon.sh"]))

@app.route("/api/scan-handshake", methods=["POST"])
def scan_handshake():
    return jsonify(run_command(["python3", "handshake.py"]))

@app.route("/api/log-sniffer", methods=["POST"])
def log_sniffer():
    return jsonify(run_command(["bash", "scan.sh"]))

@app.route("/api/deauth", methods=["POST"])
def deauth():
    data = request.get_json()
    bssid = data.get("bssid", "")
    client = data.get("client", "")
    iface = data.get("interface", "wlan0mon")
    return jsonify(run_command(["python3", "deauth.py", bssid, client, iface]))

@app.route("/api/crack", methods=["POST"])
def crack():
    data = request.get_json()
    handshake = data.get("handshake", "")
    wordlist = data.get("wordlist", "")
    return jsonify(run_command(["python3", "wifi_cracker.py", handshake, wordlist]))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)