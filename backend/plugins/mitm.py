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
