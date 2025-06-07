# backend/core/event_logger.py
import logging
import json
import os
from datetime import datetime, timezone # Use timezone-aware UTC

# This assumes that when backend.core.event_logger is imported, 'backend' is a known package.
# This should work if the application is run with `python -m backend.server`
from .. import config
logger = logging.getLogger(__name__)

def log_event(event_type: str, data: dict):
    """
    Logs a structured event to a JSON Lines file.
    """
    try:
        # Use config.EVENT_LOG_FILE directly
        log_file_path = config.EVENT_LOG_FILE

        event_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(), # UTC timestamp
            "event_type": event_type,
            "details": data  # data should be a dictionary of relevant information
        }

        # Ensure the directory for the log file exists (if it's configured with a path)
        log_dir = os.path.dirname(log_file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            logger.info(f"Created directory for event log: {log_dir}")

        with open(log_file_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event_data) + '\n')

        logger.debug(f"Logged event: {event_type}, Data: {data}")

    except Exception as e:
        # This logger is for the event_logger module itself.
        # Avoid calling log_event() from here to prevent recursion on failure.
        logger.error(f"Failed to log event type '{event_type}': {e}", exc_info=True)

if __name__ == '__main__':
    # Example Usage (for testing event_logger.py itself)
    # 1. Ensure config.py is accessible or mock it.
    # For this test, let's assume a local dummy config for simplicity if main one fails.

    class TestConfig:
        EVENT_LOG_FILE = "test_events.jsonl"
        LOG_LEVEL = "DEBUG" # For the main application logger, not event_logger's logger

    # Override config for test if needed, or ensure backend.config is found
    # For this standalone test, we'll point to a local test config.
    # This is tricky because the file expects `from .. import config`.
    # To test this file standalone, you'd typically run it from the `backend` directory:
    # python -m core.event_logger
    # Or adjust sys.path. For now, this __main__ might not fully work without path setup.

    # Simplified test logging setup for this example:
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    logger.info("Testing event_logger.py...")

    # Mockup: if this file is run directly, config might not be the "real" one.
    # Re-point EVENT_LOG_FILENAME for this specific test run.
    EVENT_LOG_FILENAME = "test_run_events.jsonl"
    if os.path.exists(EVENT_LOG_FILENAME):
        os.remove(EVENT_LOG_FILENAME) # Clean up old test file

    log_event("test_event_1", {"user": "test_user", "action": "button_click", "value": 123})
    log_event("test_event_2", {"system": "auth_service", "status": "login_failed", "reason": "bad_password"})

    try:
        with open(EVENT_LOG_FILENAME, 'r') as f:
            lines = f.readlines()
            assert len(lines) == 2
            event1 = json.loads(lines[0])
            assert event1["event_type"] == "test_event_1"
            assert event1["details"]["user"] == "test_user"
            logger.info("Event 1 written correctly.")
            event2 = json.loads(lines[1])
            assert event2["event_type"] == "test_event_2"
            assert event2["details"]["system"] == "auth_service"
            logger.info("Event 2 written correctly.")
        logger.info(f"Test events successfully written to {EVENT_LOG_FILENAME}")
    except Exception as e:
        logger.error(f"Error during test verification: {e}", exc_info=True)
    finally:
        if os.path.exists(EVENT_LOG_FILENAME):
            # os.remove(EVENT_LOG_FILENAME) # Optionally clean up
            logger.info(f"Test log file '{EVENT_LOG_FILENAME}' created. Please inspect or remove it.")

    # Test with a more complex data structure
    complex_data = {
        "target_interface": "wlan0mon",
        "scan_options": {"type": "active", "channels": [1, 6, 11]},
        "results_summary": {"networks_found": 15, "clients_associated": 3}
    }
    log_event("complex_scan_info", complex_data)
    logger.info("Logged a complex event.")
    logger.info("Test finished for event_logger.py.")
