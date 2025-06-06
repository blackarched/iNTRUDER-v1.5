# backend/core/event_logger.py
import logging
import json
from datetime import datetime, timezone # Use timezone-aware UTC

import logging
import json
import os
import sys # For issuing warnings and potentially for path adjustments in __main__
from datetime import datetime, timezone

# Initialize logger for this module
logger = logging.getLogger(__name__)

# Primary configuration import
try:
    from .. import config
    # Check if EVENT_LOG_FILE is present, if not, it might be a DummyConfig or incomplete config
    if not hasattr(config, 'EVENT_LOG_FILE'):
        logger.warning("Configuration 'config' loaded, but 'EVENT_LOG_FILE' is not defined. Using default.")
        # Provide a default on the loaded config if it's missing (e.g. if it's a test/dummy config)
        setattr(config, 'EVENT_LOG_FILE', 'default_event_log.jsonl')
except ImportError:
    logger.warning(
        "Failed to import 'config' using relative import (from .. import config). "
        "This module may not function correctly if not part of the 'backend' package. "
        "Using a fallback configuration for EVENT_LOG_FILE."
    )
    # Define a simple fallback configuration object
    class FallbackConfig:
        EVENT_LOG_FILE: str = 'fallback_event_log.jsonl'
        # Add other essential config variables if event_logger directly uses them,
        # otherwise, keep it minimal. LOG_LEVEL is usually handled by the app's main logging setup.

    config = FallbackConfig()

# Use EVENT_LOG_FILE from the (potentially fallback) config
EVENT_LOG_FILENAME: str = config.EVENT_LOG_FILE


def log_event(event_type: str, data: dict) -> None:
    """
    Logs a structured event to a JSON Lines file.

    Args:
        event_type: A string categorizing the event (e.g., 'user_login', 'file_upload').
        data: A dictionary containing event-specific information.
    """
    try:
        event_data: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "details": data
        }

        log_file_path: str = EVENT_LOG_FILENAME

        # Ensure the directory for the log file exists
        log_dir: str = os.path.dirname(log_file_path)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
                logger.info(f"Created directory for event log: {log_dir}")
            except OSError as e:
                logger.error(f"Failed to create log directory {log_dir}: {e}", exc_info=True)
                # Potentially fall back to logging in the current directory or disable logging
                # For now, we'll let the open() call fail if the directory can't be made.
                return # Exit if directory creation fails

        with open(log_file_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event_data) + '\n')

        # Use the module's logger for debug messages
        logger.debug(f"Logged event: {event_type}, Data: {data}")

    except Exception as e:
        # Use the module's logger for error messages
        logger.error(f"Failed to log event type '{event_type}': {e}", exc_info=True)

if __name__ == '__main__':
    # This block is for testing the event_logger.py module directly.
    # It demonstrates how to use log_event and verifies its output.
    # Important: For this to run correctly, it might require adjusting the Python path
    # if the `from .. import config` fails, or by running as a module:
    # `python -m backend.core.event_logger` from the project root.

    # Setup basic logging for the test execution (distinct from app's logging)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout # Log to stdout for testing
    )

    logger.info("Starting test run for event_logger.py...")

    # Define a distinct test event log filename
    TEST_EVENT_LOG_FILENAME = "test_event_logger_output.jsonl"

    # Override EVENT_LOG_FILENAME for this test session
    # This is a bit of a hack for __main__ but makes testing self-contained.
    # A better approach for testing involves using a dedicated test configuration
    # or mocking the config object.
    original_event_log_filename = EVENT_LOG_FILENAME
    EVENT_LOG_FILENAME = TEST_EVENT_LOG_FILENAME
    logger.info(f"Test events will be logged to: {TEST_EVENT_LOG_FILENAME}")

    # Clean up any previous test log file
    if os.path.exists(TEST_EVENT_LOG_FILENAME):
        try:
            os.remove(TEST_EVENT_LOG_FILENAME)
            logger.info(f"Removed existing test log file: {TEST_EVENT_LOG_FILENAME}")
        except OSError as e:
            logger.warning(f"Could not remove old test log file {TEST_EVENT_LOG_FILENAME}: {e}")

    # Log some test events
    log_event("test_startup", {"module": "event_logger", "status": "testing"})
    log_event("user_action", {"user_id": "tester01", "action": "create_document", "doc_id": "doc123"})
    complex_data_test = {
        "process_id": 12345,
        "metrics": {"cpu_usage": 0.75, "memory_rss_mb": 256},
        "tags": ["critical", "data_processing"]
    }
    log_event("system_metric", complex_data_test)

    # Verify the content of the test log file
    try:
        with open(TEST_EVENT_LOG_FILENAME, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        assert len(lines) == 3, f"Expected 3 log entries, got {len(lines)}"
        logger.info(f"Found {len(lines)} lines in the test log file.")

        event1 = json.loads(lines[0])
        assert event1["event_type"] == "test_startup"
        assert event1["details"]["module"] == "event_logger"
        logger.info("Test event 1 verified.")

        event2 = json.loads(lines[1])
        assert event2["event_type"] == "user_action"
        assert event2["details"]["user_id"] == "tester01"
        logger.info("Test event 2 verified.")

        event3 = json.loads(lines[2])
        assert event3["event_type"] == "system_metric"
        assert event3["details"]["metrics"]["cpu_usage"] == 0.75
        logger.info("Test event 3 (complex data) verified.")

        logger.info(f"All test events successfully written and verified in {TEST_EVENT_LOG_FILENAME}.")

    except FileNotFoundError:
        logger.error(f"Test log file {TEST_EVENT_LOG_FILENAME} was not created.", exc_info=True)
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from {TEST_EVENT_LOG_FILENAME}.", exc_info=True)
    except AssertionError as e:
        logger.error(f"Test assertion failed: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"An unexpected error occurred during test verification: {e}", exc_info=True)
    finally:
        # Clean up the test log file after verification
        if os.path.exists(TEST_EVENT_LOG_FILENAME):
            try:
                os.remove(TEST_EVENT_LOG_FILENAME)
                logger.info(f"Cleaned up test log file: {TEST_EVENT_LOG_FILENAME}")
            except OSError as e:
                logger.warning(f"Could not clean up test log file {TEST_EVENT_LOG_FILENAME}: {e}. Please remove it manually.")
        # Restore original EVENT_LOG_FILENAME if it was changed
        EVENT_LOG_FILENAME = original_event_log_filename

    logger.info("Test run for event_logger.py finished.")

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
