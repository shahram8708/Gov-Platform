"""Centralized logging with rotation suitable for audit trails."""
import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional


def init_logging(app) -> logging.Logger:
    log_dir = app.config.get("LOG_DIR") or os.path.join(app.instance_path, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "app.log")

    level_name = (app.config.get("LOG_LEVEL") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(module)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)

    logger = logging.getLogger(app.name)
    logger.setLevel(level)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.propagate = False

    # Flask's built-in logger
    app.logger.handlers = logger.handlers
    app.logger.setLevel(level)

    logger.info("Logging initialized", extra={"path": log_path})
    return logger
