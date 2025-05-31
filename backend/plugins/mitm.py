# backend/plugins/mitm.py
"""
Module: mitm
Implements a Man-in-the-Middle proxy integration using mitmproxy.
"""
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
import threading
import logging
from ..core.event_logger import log_event # Import for event logging

# Configure logging for this module
logger = logging.getLogger(__name__) # Inherits root logger configuration

class MitmProxy:
    def __init__(self, listen_port: int = 8081, mode: str = 'transparent', upstream_proxy: str = None):
        logger.info(f"Initializing MitmProxy: port={listen_port}, mode={mode}, upstream={upstream_proxy}")
        log_event("mitm_proxy_init", {"listen_port": listen_port, "mode": mode, "upstream_proxy": upstream_proxy})
        opts = options.Options(listen_host='0.0.0.0', listen_port=listen_port, mode=mode)
        if upstream_proxy:
            opts.upstream_proxy = upstream_proxy
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False) # Disable mitmproxy's own terminal logging if using our handler
        self.thread = None # To keep track of the mitmproxy thread

    def start(self):
        """Start mitmproxy in a background thread."""
        if self.thread and self.thread.is_alive():
            logger.warning("MITM proxy start requested, but it appears to be already running.")
            return

        # Define the proxy runner function
        def run_proxy():
            logger.info(f"Mitmproxy thread: Starting mitmproxy instance on port {self.master.options.listen_port} in mode '{self.master.options.mode}'...")
            try:
                self.master.run() # This blocks until shutdown
                logger.info("Mitmproxy thread: master.run() completed normally.")
            except Exception as e: # Catch any exception from mitmproxy.master.run()
                # Check if it's a KeyboardInterrupt (Ctrl+C) which might be expected if server is stopped this way
                if isinstance(e, KeyboardInterrupt):
                    logger.info("Mitmproxy thread: KeyboardInterrupt received, mitmproxy stopping.")
                else:
                    logger.error(f"Mitmproxy thread: Exception during mitmproxy run: {e}", exc_info=True)
            finally:
                logger.info("Mitmproxy thread: Finished.")

        self.thread = threading.Thread(target=run_proxy, daemon=True, name="MitmProxyThread")
        self.thread.start()
        logger.info(f"MitmProxy thread '{self.thread.name}' has been started.")
        log_event("mitm_proxy_started", {"listen_port": self.master.options.listen_port, "mode": self.master.options.mode})

    def shutdown(self):
        if not self.thread or not self.thread.is_alive():
            logger.info("MITM proxy shutdown requested, but it's not running or thread already stopped.")
            log_event("mitm_proxy_shutdown_noop", {"message": "Not running or thread stopped."})
            return

        logger.info("Attempting to shut down mitmproxy master instance...")
        log_event("mitm_proxy_stopping", {"listen_port": self.master.options.listen_port if self.master else "unknown"})
        try:
            self.master.shutdown()
            logger.info("Mitmproxy master instance shutdown signal sent.")
        except Exception as e:
            logger.error(f"Exception while calling mitmproxy master.shutdown(): {e}", exc_info=True)
            log_event("mitm_proxy_shutdown_error", {"error": str(e)})

        # Wait for the thread to finish
        logger.debug(f"Waiting for MitmProxy thread '{self.thread.name}' to join...")
        self.thread.join(timeout=10) # Wait for 10 seconds for graceful exit

        if self.thread.is_alive():
            logger.warning(f"MitmProxy thread '{self.thread.name}' did not join after 10s timeout. Mitmproxy might be taking longer to shut down or is stuck.")
            log_event("mitm_proxy_shutdown_timeout", {"thread_name": self.thread.name})
        else:
            logger.info(f"MitmProxy thread '{self.thread.name}' joined successfully.")
            log_event("mitm_proxy_stopped", {"listen_port": self.master.options.listen_port if self.master else "unknown", "status": "success"})

        self.thread = None # Clear the thread reference
        logger.info("MitmProxy shutdown process completed.")
