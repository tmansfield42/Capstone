#!/usr/bin/env python3
"""
utils/logger.py - Centralised Logging Setup

Configures the "probepoint" root logger with two handlers:
  - Console (stdout): INFO level — shows progress during a scan
  - File (logs/probepoint.log): DEBUG level — full detail for debugging

The log file rotates daily and the last 7 days are retained.
The logs directory is created automatically if it does not exist.

Standalone usage (smoke-test):
  python3 utils/logger.py
"""

from __future__ import annotations

import logging
import sys
import yaml
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOGGER_NAME = "probepoint"
LOG_FILENAME = "probepoint.log"
DEFAULT_LOGS_DIR = "logs"

CONSOLE_LEVEL = logging.INFO
FILE_LEVEL = logging.DEBUG
BACKUP_COUNT = 7  # days of log history to retain

CONSOLE_FORMAT = "%(asctime)s [%(levelname)-8s] %(message)s"
FILE_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s:%(lineno)d — %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

CONFIG_PATH = Path(__file__).parent.parent / "config" / "settings.yaml"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_logger(config: dict) -> logging.Logger:
    """
    Configure and return the ProbePoint application logger.

    Safe to call multiple times — handlers are only added once.
    The logs directory is created if it does not already exist.

    Handler summary:
      - StreamHandler  → stdout, INFO level
      - TimedRotatingFileHandler → logs/probepoint.log, DEBUG level,
                                   rotates midnight, keeps 7 days

    Args:
        config: Parsed settings.yaml dict. Used to resolve the logs
                directory from config['storage']['logs_dir']; falls
                back to "logs/" if the key is absent or empty.

    Returns:
        Configured logging.Logger named "probepoint".
    """
    logger = logging.getLogger(LOGGER_NAME)

    # Avoid adding duplicate handlers if setup_logger is called more than once
    if logger.handlers:
        return logger

    # Resolve logs directory
    logs_dir = (
        config.get("storage", {}).get("logs_dir") or DEFAULT_LOGS_DIR
    )
    logs_path = Path(logs_dir)
    logs_path.mkdir(parents=True, exist_ok=True)

    log_file = logs_path / LOG_FILENAME

    # Root logger level must be at least as permissive as the most verbose handler
    logger.setLevel(FILE_LEVEL)

    # ------------------------------------------------------------------
    # Console handler — INFO and above, human-readable progress output
    # ------------------------------------------------------------------
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(CONSOLE_LEVEL)
    console_handler.setFormatter(logging.Formatter(CONSOLE_FORMAT, DATE_FORMAT))

    # ------------------------------------------------------------------
    # File handler — DEBUG and above, daily rotation, 7-day retention
    # ------------------------------------------------------------------
    file_handler = TimedRotatingFileHandler(
        filename=str(log_file),
        when="midnight",      # rotate at midnight
        interval=1,           # every 1 day
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
        utc=False,            # use local time for rotation
    )
    file_handler.setLevel(FILE_LEVEL)
    file_handler.setFormatter(logging.Formatter(FILE_FORMAT, DATE_FORMAT))

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger.debug(f"Logger initialised — file: {log_file}")
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Return a child logger under the "probepoint" namespace.

    Call setup_logger() at least once before using this helper.
    Each module can call get_logger(__name__) to get a prefixed logger
    that feeds into the shared handlers configured by setup_logger().

    Args:
        name: Optional child name. If None, returns the root "probepoint"
              logger directly.

    Returns:
        logging.Logger in the "probepoint" hierarchy.
    """
    if name is None:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Load config if available, otherwise pass empty dict for defaults
    config: dict = {}
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r") as f:
                config = yaml.safe_load(f) or {}
        except yaml.YAMLError:
            pass

    log = setup_logger(config)

    log.debug("DEBUG message — appears in log file only")
    log.info("INFO message — appears on console and in log file")
    log.warning("WARNING message")
    log.error("ERROR message")

    logs_dir = config.get("storage", {}).get("logs_dir") or DEFAULT_LOGS_DIR
    print(f"\nLogger OK — log file: {Path(logs_dir) / LOG_FILENAME}")
