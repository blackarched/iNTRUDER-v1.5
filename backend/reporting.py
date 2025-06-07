from . import config # In backend/reporting.py
import os
import json
import logging
from datetime import datetime, timezone # Ensure timezone for report generation timestamp consistency

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, event_log_file=None):
        # Determine event log file path
        # This needs to be robust in case config.EVENT_LOG_FILE isn't set, though it should be.
        # config.EVENT_LOG_FILE is expected to be set by the main application configuration.
        configured_event_log = config.EVENT_LOG_FILE # Will raise AttributeError if not set

        # If event_log_file is provided as an argument, it overrides config.
        # Otherwise, use the one from config (or default if config lacks it).
        self.event_log_file = event_log_file if event_log_file is not None else configured_event_log

        logger.info(f"ReportGenerator initialized. Using event log file: {self.event_log_file}")

        # Determine reports directory
        # config.REPORTS_DIR is expected to be set by the main application configuration.
        self.reports_dir = config.REPORTS_DIR # Will raise AttributeError if not set

        if not os.path.isabs(self.reports_dir):
            # Assuming project root is the current working directory when server starts
            # This makes reports_dir relative to project root.
            # For robustness, consider making it absolute if needed, e.g., based on script location.
            # For now, relative to CWD (expected to be /app) is fine.
            self.reports_dir = os.path.join(os.getcwd(), self.reports_dir)
            logger.debug(f"Reports directory resolved to absolute path: {self.reports_dir}")

        if not os.path.exists(self.reports_dir):
            try:
                os.makedirs(self.reports_dir)
                logger.info(f"Created reports directory: {self.reports_dir}")
            except OSError as e:
                logger.error(f"Failed to create reports directory {self.reports_dir}: {e}", exc_info=True)
                # Fallback to current dir if reports_dir cannot be made.
                # Using os.getcwd() which should be /app if server is run from root.
                self.reports_dir = os.getcwd()
                logger.warning(f"Reports will be saved to current directory: {self.reports_dir} due to error creating dedicated reports folder.")

        logger.info(f"Reports will be saved in: {self.reports_dir}")

    # Placeholder for _read_events
    def _read_events(self) -> list[dict]:
        events = []
        if not os.path.exists(self.event_log_file):
            logger.error(f"Event log file not found: {self.event_log_file}")
            return events

        try:
            with open(self.event_log_file, 'r', encoding='utf-8') as f:
                for line_number, line in enumerate(f, 1):
                    line = line.strip()
                    if not line: # Skip empty lines
                        continue
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to decode JSON from line {line_number} in {self.event_log_file}: {e}. Line content: '{line[:100]}...'") # Log first 100 chars
            logger.info(f"Successfully read {len(events)} events from {self.event_log_file}")
        except FileNotFoundError: # Should be caught by os.path.exists, but good to have defense in depth
            logger.error(f"Event log file disappeared during read: {self.event_log_file}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while reading event log file {self.event_log_file}: {e}", exc_info=True)
        return events

    # Placeholder for generate_json_report
    def generate_json_report(self, filename_prefix="session_report") -> str | None:
        events = self._read_events()
        if not events:
            logger.info("No events found to generate JSON report.")
            return None

        try:
            # Ensure reports_dir exists (it should from __init__, but check again)
            if not os.path.exists(self.reports_dir):
                os.makedirs(self.reports_dir)
                logger.info(f"Reports directory was missing, recreated: {self.reports_dir}")

            timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            report_filename = f"{filename_prefix}_{timestamp_str}.json"
            report_filepath = os.path.join(self.reports_dir, report_filename)

            report_content = {
                "report_generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "event_log_source": self.event_log_file,
                "total_events": len(events),
                "session_events": events
            }

            with open(report_filepath, 'w', encoding='utf-8') as f:
                json.dump(report_content, f, indent=4, ensure_ascii=False)

            logger.info(f"JSON report generated successfully: {report_filepath}")
            return report_filepath
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}", exc_info=True)
            return None

    # Placeholder for generate_markdown_report
    def generate_markdown_report(self, filename_prefix="session_report") -> str | None:
        events = self._read_events()
        if not events:
            logger.info("No events found to generate Markdown report.")
            return None

        try:
            if not os.path.exists(self.reports_dir): # Ensure reports_dir exists
                os.makedirs(self.reports_dir)
                logger.info(f"Reports directory was missing, recreated: {self.reports_dir}")

            report_timestamp_obj = datetime.now(timezone.utc)
            report_timestamp_str_file = report_timestamp_obj.strftime('%Y%m%d_%H%M%S')
            report_timestamp_str_title = report_timestamp_obj.strftime('%Y-%m-%d %H:%M:%S UTC')

            report_filename = f"{filename_prefix}_{report_timestamp_str_file}.md"
            report_filepath = os.path.join(self.reports_dir, report_filename)

            md_lines = []
            md_lines.append(f"# Penetration Test Session Report - {report_timestamp_str_title}")
            md_lines.append(f"\n*Event log source: `{self.event_log_file}`*")
            md_lines.append(f"*Total events processed: {len(events)}*\n")

            md_lines.append("## Key Events Summary:\n")

            key_event_found = False
            for event in events:
                ts = event.get("timestamp", "N/A")
                event_type = event.get("event_type", "unknown_event")
                details = event.get("details", {})

                summary_line = None
                if event_type == "scan_completed":
                    summary_line = f"- **Scan Completed** (Time: {ts}): Interface `{details.get('interface', 'N/A')}` found {details.get('network_count', 0)} networks and {details.get('client_count', 0)} clients over {details.get('duration_seconds', 'N/A')}s." # Changed 'duration' to 'duration_seconds'
                    key_event_found = True
                elif event_type == "handshake_capture_completed" and details.get('success'):
                    ssid = details.get('ssid', 'N/A')
                    bssid = details.get('bssid', 'N/A')
                    target_id = ssid if ssid !='N/A' else bssid
                    file_path = details.get('file', 'N/A')
                    summary_line = f"- **Handshake Captured** (Time: {ts}): For target `{target_id}`. File: `{file_path}`."
                    key_event_found = True
                elif event_type == "crack_attempt_completed" and details.get('success') and details.get('password_found'):
                    summary_line = f"- **Password Cracked** (Time: {ts}): For handshake file `{details.get('handshake_file', 'N/A')}`. Wordlist: `{details.get('wordlist_used', 'N/A')}`."
                    # DO NOT log the actual password in the report: details.get('password_found')
                    key_event_found = True
                elif event_type == "mac_address_changed":
                    summary_line = f"- **MAC Address Changed** (Time: {ts}): Interface `{details.get('interface', 'N/A')}` from `{details.get('old_mac', 'N/A')}` to `{details.get('new_mac', 'N/A')}` (Method: {details.get('method', 'N/A')})."
                    key_event_found = True
                elif event_type == "mac_address_reverted":
                    summary_line = f"- **MAC Address Reverted** (Time: {ts}): Interface `{details.get('interface', 'N/A')}` to `{details.get('reverted_to_mac', 'N/A')}`."
                    key_event_found = True
                elif event_type == "rogue_ap_started":
                     summary_line = f"- **Rogue AP Started** (Time: {ts}): Interface `{details.get('interface', 'N/A')}`, SSID `{details.get('ssid', 'N/A')}`."
                     key_event_found = True
                elif event_type == "rogue_ap_stopped":
                     summary_line = f"- **Rogue AP Stopped** (Time: {ts}): Interface `{details.get('interface', 'N/A')}`, SSID `{details.get('ssid', 'N/A')}`."
                     key_event_found = True

                if summary_line:
                    md_lines.append(summary_line)

            if not key_event_found:
                md_lines.append("*No major reconnaissance or attack events found in this session to summarize.*\n")

            # Optionally, add a section for all events if desired (can be very verbose)
            # md_lines.append("\n## All Logged Events:\n")
            # for event in events:
            #     md_lines.append(f"```json\n{json.dumps(event, indent=2)}\n```\n")

            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(md_lines))

            logger.info(f"Markdown report generated successfully: {report_filepath}")
            return report_filepath
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}", exc_info=True)
            return None

if __name__ == '__main__':
    # Basic test setup for ReportGenerator
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Create a dummy config for testing if the main one isn't easily accessible
    # This is simplified; real testing might involve more elaborate config mocking or path setup.
    class DummyConfig:
        EVENT_LOG_FILE = "test_report_events.jsonl"
        REPORTS_DIR = "test_reports_output"
        LOG_LEVEL = "DEBUG"

    # Override config for this test context
    original_config = config # Save original config if it exists
    config = DummyConfig()

    logger.info(f"--- Testing ReportGenerator with dummy config ---")
    logger.info(f"Event log for test: {config.EVENT_LOG_FILE}")
    logger.info(f"Reports directory for test: {config.REPORTS_DIR}")

    # Ensure the dummy event log and reports dir are clean for the test
    if os.path.exists(config.EVENT_LOG_FILE):
        os.remove(config.EVENT_LOG_FILE)
    if os.path.exists(config.REPORTS_DIR):
        shutil.rmtree(config.REPORTS_DIR) # Use shutil to remove directory and contents

    # Create some dummy events for testing
    dummy_events_data = [
        {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "test_event_1", "details": {"info": "detail1"}},
        {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "test_event_2", "details": {"info": "detail2", "value": 100}},
        "this is not a valid json line\n", # Test invalid JSON line
        {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "test_event_3", "details": {"info": "detail3"}},
    ]
    with open(config.EVENT_LOG_FILE, 'w', encoding='utf-8') as f:
        for event in dummy_events_data:
            if isinstance(event, dict):
                f.write(json.dumps(event) + '\n')
            else:
                f.write(str(event)) # Write invalid line as is

    report_gen = ReportGenerator(event_log_file=config.EVENT_LOG_FILE) # Override to use test log

    # Test _read_events (will be implemented next)
    # events = report_gen._read_events()
    # logger.info(f"Read {len(events)} events (expected 3 valid).")
    # assert len(events) == 3, f"Expected 3 valid events, got {len(events)}"

    # Test generate_json_report (will be implemented next)
    # json_path = report_gen.generate_json_report(filename_prefix="test_json_report")
    # if json_path:
    #     logger.info(f"JSON report generated: {json_path}")
    #     assert os.path.exists(json_path)
    # else:
    #     logger.error("JSON report generation failed or produced no output.")

    # Test generate_markdown_report (will be implemented next)
    # md_path = report_gen.generate_markdown_report(filename_prefix="test_md_report")
    # if md_path:
    #     logger.info(f"Markdown report generated: {md_path}")
    #     assert os.path.exists(md_path)
    # else:
    #     logger.error("Markdown report generation failed or produced no output.")

    logger.info(f"--- ReportGenerator Test Placeholders Executed ---")

    # Clean up test files and directory
    # if os.path.exists(config.EVENT_LOG_FILE):
    #     os.remove(config.EVENT_LOG_FILE)
    # if os.path.exists(config.REPORTS_DIR):
    #     shutil.rmtree(config.REPORTS_DIR)
    # logger.info("Cleaned up test files/directories.")

    config = original_config # Restore original config
    logger.info("--- ReportGenerator Test Completed ---")
