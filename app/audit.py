"""Structured (JSON) logging setup so a SIEM can parse this straight off
stdout without a separate log-shipping transform."""
from __future__ import annotations

import logging
import sys

from pythonjsonlogger import jsonlogger

from app.config import settings


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(name)s %(levelname)s %(message)s",
        rename_fields={"asctime": "timestamp", "levelname": "level", "name": "logger"},
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level.upper())
