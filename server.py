# server.py
"""
Main server entrypoint for iNTRUDER v1.5 with integrated plugins:
- Rogue AP
- MITM proxy
- WPS attack
- Deauth attack
- Handshake capture
- Wi-Fi cracking
Provides RESTful API endpoints and WebSocket events for dashboard control.
"""
import os
import signal
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from backend.plugins.rogue_ap import RogueAP
from backend.plugins.mitm import MitmProxy
from backend.plugins.wps_attack import WPSAttack
from backend.deauth_attack import DeauthAttack
from backend.handshake import HandshakeCapture
from backend.wifi_cracker import WifiCracker

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("server")

# Flask + SocketIO setup
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global process/state holders
_services = {}

# Graceful shutdown
def shutdown_handler(signum, frame):
    logger.info("Shutting down iNTRUDER server and all services...")
    for name, svc in _services.items():
        try:
            svc.shutdown() if hasattr(svc, 'shutdown') else svc.cleanup()
            logger.info(f"Stopped {name}")
        except Exception:
            logger.exception(f"Error stopping {name}")
    os._exit(0)

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

# Endpoint: Start Rogue AP
@app.route('/api/rogue_ap/start', methods=['POST'])
def api_start_rogue_ap():
    data = request.json
    iface = data.get('iface')
    ssid = data.get('ssid')
    channel = data.get('channel', 6)

    ap = RogueAP(iface=iface, ssid=ssid, channel=channel)
    procs = ap.start_services()
    _services['rogue_ap'] = ap
    return jsonify({'status': 'running', 'procs': list(procs.keys())}), 200

# Endpoint: Stop Rogue AP
@app.route('/api/rogue_ap/stop', methods=['POST'])
def api_stop_rogue_ap():
    ap = _services.pop('rogue_ap', None)
    if not ap:
        return jsonify({'error': 'Rogue AP not running'}), 400
    ap.cleanup()
    return jsonify({'status': 'stopped'}), 200

# Endpoint: Start MITM Proxy
@app.route('/api/mitm/start', methods=['POST'])
def api_start_mitm():
    data = request.json
    port = data.get('port', 8081)
    mode = data.get('mode', 'transparent')

    mitm = MitmProxy(listen_port=port, mode=mode)
    mitm.start()
    _services['mitm'] = mitm
    return jsonify({'status': 'running', 'port': port}), 200

# Endpoint: Stop MITM Proxy
@app.route('/api/mitm/stop', methods=['POST'])
def api_stop_mitm():
    mitm = _services.pop('mitm', None)
    if not mitm:
        return jsonify({'error': 'MITM not running'}), 400
    mitm.shutdown()
    return jsonify({'status': 'stopped'}), 200

# Endpoint: Start WPS Attack
@app.route('/api/wps/start', methods=['POST'])
def api_start_wps():
    data = request.json
    iface = data.get('iface')
    bssid = data.get('bssid')
    timeout = data.get('timeout', 3600)
    multi = data.get('multi', False)

    wps = WPSAttack(iface=iface, target_bssid=bssid)
    _services['wps'] = wps
    code = wps.run(timeout=timeout, multi=multi)
    return jsonify({'status': 'completed', 'exit_code': code}), 200

# Endpoint: Deauthentication Attack
@app.route('/api/deauth/start', methods=['POST'])
def api_start_deauth():
    data = request.json
    iface = data.get('iface')
    target = data.get('target')  # MAC to deauth
    count = data.get('count', 10)

    deauth = DeauthAttack(iface=iface, target_mac=target, count=count)
    _services['deauth'] = deauth
    result = deauth.run()
    return jsonify({'status': 'completed', 'sent': result}), 200

# Endpoint: Capture Handshake
@app.route('/api/handshake/start', methods=['POST'])
def api_start_handshake():
    data = request.json
    iface = data.get('iface')
    ssid = data.get('ssid')

    hs = HandshakeCapture(iface=iface, ssid=ssid)
    _services['handshake'] = hs
    path = hs.capture()
    return jsonify({'status': 'captured', 'file': path}), 200

# Endpoint: Wi-Fi Cracking
@app.route('/api/crack/start', methods=['POST'])
def api_start_crack():
    data = request.json
    handshake_file = data.get('handshake_file')
    wordlist = data.get('wordlist')

    cracker = WifiCracker(handshake_file=handshake_file, wordlist=wordlist)
    _services['cracker'] = cracker
    passwd = cracker.run()
    return jsonify({'status': 'completed', 'password': passwd}), 200

# Health check
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200

# SocketIO example: real-time logs
@socketio.on('connect')
def on_connect():
    logger.info('Dashboard client connected')
    socketio.emit('status', {'services': list(_services.keys())})

if __name__ == '__main__':
    port = int(os.environ.get('INTRUDER_PORT', 5000))
    debug = os.environ.get('INTRUDER_DEBUG', 'False') == 'True'
    logger.info(f"Starting iNTRUDER server on port {port}, debug={debug}")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug)
