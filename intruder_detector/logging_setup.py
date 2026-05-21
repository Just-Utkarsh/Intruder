"""Centralized logging configuration for daemon and CLI tools."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from intruder_detector.config import get_data_dir


def setup_logging(level: str = "INFO", silent: bool = False, name: str = "intruder-detector") -> logging.Logger:
    log_dir = get_data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "daemon.log"

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    if not silent:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(formatter)
        console.setLevel(getattr(logging, level.upper(), logging.INFO))
        logger.addHandler(console)

    return logger
