#!/usr/bin/env python3
"""
Network scanning utility using airodump-ng.

This script provides functionality to scan for wireless networks using airodump-ng,
save the results in various formats (pcap, csv, logjson), and manage scan duration
and output locations. It is designed to be run with root privileges.
"""

import os
import argparse
import logging
import time
import sys
import subprocess
import json # For printing results if run as main

# Initialize logger for this script
logger = logging.getLogger(__name__)

# Attempt to import backend.config for default paths, with fallback
try:
    from backend import config as app_config
    logger.debug("Successfully imported backend.config")
except ImportError:
    logger.warning("Could not import backend.config. Using fallback configuration for default paths.")
    class FallbackConfig:
        """Fallback configuration if main app config is not available."""
        REPORTS_DIR: str = "./scan_reports/" # Default directory for scan reports
        # LOG_FILE could also be defined here if needed for file logging in fallback mode
    app_config = FallbackConfig() # type: ignore

def setup_logging(log_level_str: str = "INFO"):
    """Configures basic logging for the script."""
    numeric_level = getattr(logging, log_level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        stream=sys.stdout # Log to stdout by default
    )
    # Optionally, could add a FileHandler if a log file path is determined from config

def scan_networks(interface: str, output_prefix: str, scan_timeout: int, reports_dir: str) -> dict:
    """
    Scans for wireless networks using airodump-ng.

    Args:
        interface: The wireless interface to use for scanning.
        output_prefix: Prefix for the output scan files.
        scan_timeout: Duration of the scan in seconds.
        reports_dir: Directory where scan result files will be saved.

    Returns:
        A dictionary containing the status of the scan, paths to any created
        output files, and an error message if applicable.
    """
    logger.info(
        f"Starting network scan on interface '{interface}' for {scan_timeout} seconds. "
        f"Output will be saved in '{reports_dir}' with prefix '{output_prefix}'."
    )

    timestamp_str = time.strftime('%Y%m%d_%H%M%S')
    # Base path for airodump-ng output files (airodump-ng appends e.g., '-01.csv')
    airodump_file_base = os.path.join(reports_dir, f"{output_prefix}{timestamp_str}")

    # Ensure the specific output directory for these scan files exists
    # os.path.dirname(airodump_file_base) is effectively reports_dir here,
    # which should be created in __main__ before calling this function.
    # If airodump_file_base included subdirectories, this would be more critical:
    # os.makedirs(os.path.dirname(airodump_file_base), exist_ok=True)
    # For now, ensuring reports_dir in __main__ is sufficient.

    # Command to execute airodump-ng.
    # sudo is not included here; the script itself should be run with root privileges.
    cmd = [
        "airodump-ng", interface,
        "--write-interval", "5",  # How often to write files (seconds)
        "--output-format", "pcap,csv,logjson",  # Request pcap, csv, and logjson formats
        "--write", airodump_file_base  # Base name for output files
    ]

    logger.debug(f"Executing command: {' '.join(cmd)}")
    status_message = "Scan initiated."
    output_files_found = []
    error_message = ""
    success_status = "pending" # pending, success, error, timeout

    try:
        process = subprocess.run(
            cmd,
            timeout=scan_timeout,
            capture_output=True, # Capture stdout/stderr
            text=True,           # Decode as text
            check=False          # Do not raise exception on non-zero exit, handle manually
        )

        logger.debug(f"airodump-ng stdout:\n{process.stdout}")
        if process.stderr: # airodump-ng often prints status to stderr
            logger.debug(f"airodump-ng stderr:\n{process.stderr}")

        if process.returncode == 0:
            status_message = "Scan completed successfully."
            success_status = "success"
            logger.info(status_message)
        else:
            # Non-zero return code could be due to various reasons (e.g., interface issues, permissions)
            # or if it was terminated by timeout (though TimeoutExpired should catch that first).
            status_message = f"Scan process finished with return code {process.returncode}."
            error_message = process.stderr.strip() if process.stderr else "Unknown error, check logs."
            success_status = "error"
            logger.warning(f"{status_message} Stderr: {error_message}")

    except FileNotFoundError:
        status_message = "Error: airodump-ng command not found. Please ensure it is installed and in PATH."
        error_message = "airodump-ng not found."
        success_status = "error"
        logger.error(status_message, exc_info=True)
    except subprocess.TimeoutExpired:
        status_message = f"Scan timed out after {scan_timeout} seconds as scheduled."
        success_status = "success" # Timeout is an expected way to end a scan
        logger.info(status_message)
        # Process might be still running, ensure it's terminated if needed,
        # though subprocess.run should handle this for the main process.
        # If airodump-ng spawns children that don't get terminated, more complex handling is needed.
    except Exception as e:
        status_message = f"An unexpected error occurred during scan: {e}"
        error_message = str(e)
        success_status = "error"
        logger.error(status_message, exc_info=True)
    finally:
        # Attempt to find files created by airodump-ng
        # Airodump-ng typically appends "-01" before the extension for the first set of files.
        # It might create multiple if run for a very long time or if files roll over.
        # For this typical scan duration, we expect one set.
        expected_base_with_seq = f"{airodump_file_base}-01"
        possible_extensions = [".csv", ".pcap", ".log.json"] # ".kismet.csv", ".kismet.netxml" are also possible

        # Also check for files without the "-01" sequence number, as airodump-ng behavior can vary or be configured
        # For simplicity, this example primarily looks for "-01" but a more robust search might be needed.
        # For the 'logjson' format, airodump-ng creates a directory and places files inside.
        # Example: airodump_file_base-01.log.json (file) or airodump_file_base.log.json (directory)

        try:
            if os.path.exists(reports_dir):
                for item_name in os.listdir(reports_dir):
                    # Check for primary files like base-01.csv, base-01.pcap
                    if item_name.startswith(os.path.basename(expected_base_with_seq)):
                        output_files_found.append(os.path.join(reports_dir, item_name))
                    # Check for logjson directory (e.g. base.log.json/ or base-01.log.json/)
                    # Airodump might create base.log.json as a directory for logjson output
                    elif item_name == f"{os.path.basename(airodump_file_base)}.log.json" and \
                         os.path.isdir(os.path.join(reports_dir, item_name)):
                        logjson_dir_path = os.path.join(reports_dir, item_name)
                        output_files_found.append(logjson_dir_path) # Add the directory itself
                        # Optionally, list files within this directory too
                        for logjson_file in os.listdir(logjson_dir_path):
                             output_files_found.append(os.path.join(logjson_dir_path, logjson_file))
                    elif item_name.startswith(os.path.basename(airodump_file_base)) and item_name.endswith(".log.json") and \
                         os.path.isdir(os.path.join(reports_dir, item_name)): # Corrected item_.name to item_name
                        logjson_dir_path = os.path.join(reports_dir, item_name)
                        output_files_found.append(logjson_dir_path)
                        for logjson_file in os.listdir(logjson_dir_path):
                             output_files_found.append(os.path.join(logjson_dir_path, logjson_file))


                if output_files_found:
                    logger.info(f"Scan output files found: {output_files_found}")
                else:
                    logger.warning(f"No output files matching pattern '{expected_base_with_seq}*' or '{os.path.basename(airodump_file_base)}.log.json' found in '{reports_dir}'. Airodump-ng might not have created them as expected.")
        except Exception as e_file_scan:
            logger.error(f"Error while scanning for output files: {e_file_scan}", exc_info=True)


    return {
        "status": success_status,
        "message": status_message,
        "output_directory": reports_dir,
        "output_file_base": airodump_file_base,
        "output_files_found": output_files_found,
        "error_details": error_message
    }

if __name__ == "__main__":
    # Setup basic logging for direct execution
    # More sophisticated logging can be configured in a main application
    setup_logging() # Default to INFO

    parser = argparse.ArgumentParser(
        description="Scan for wireless networks using airodump-ng.",
        epilog="Note: This script typically requires root privileges to access wireless interfaces for scanning."
    )
    parser.add_argument(
        "interface",
        type=str,
        help="Wireless interface to use for scanning (must be in monitor mode)."
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default="scan_results_",
        help="Prefix for the output scan files. A timestamp will be appended. (Default: 'scan_results_')"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Duration of the scan in seconds. (Default: 60)"
    )
    parser.add_argument(
        "--dir",
        type=str,
        default=app_config.REPORTS_DIR, # Use config default or fallback
        help=f"Directory to save scan results. (Default: from app config or '{FallbackConfig.REPORTS_DIR}')"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG level logging."
    )

    args = parser.parse_args()

    if args.verbose:
        setup_logging("DEBUG") # Re-setup logging if verbose is enabled
        logger.setLevel(logging.DEBUG) # Ensure current logger instance is also set

    logger.debug(f"Parsed arguments: {args}")

    # Ensure the main reports directory exists
    try:
        os.makedirs(args.dir, exist_ok=True)
        logger.info(f"Ensured output directory exists: {args.dir}")
    except OSError as e:
        logger.error(f"Failed to create output directory '{args.dir}': {e}. Please check permissions or path.", exc_info=True)
        sys.exit(1)
    except Exception as e_dir:
        logger.error(f"An unexpected error occurred creating directory '{args.dir}': {e_dir}", exc_info=True)
        sys.exit(1)


    # Call the scan function
    scan_result = scan_networks(
        interface=args.interface,
        output_prefix=args.prefix,
        scan_timeout=args.timeout,
        reports_dir=args.dir
    )

    # Print the result as JSON
    print(json.dumps(scan_result, indent=4))

    if scan_result["status"] == "error":
        logger.error("Scan reported an error. Exiting with status 1.")
        sys.exit(1)
    elif scan_result["status"] == "pending": # Should ideally not happen if logic is complete
        logger.warning("Scan status is unexpectedly 'pending'. Exiting with status 1.")
        sys.exit(1)

    logger.info("Scan script finished.")
    sys.exit(0)
