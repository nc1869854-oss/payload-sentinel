"""
config/logger.py

Central logging configuration for Payload Capture Suite.

Every module imports from here instead of using print() or
creating its own logger. This keeps log output consistent and
makes it easy to route everything to a file or a log viewer.

Usage:
    from config.logger import get_logger
    log = get_logger(__name__)
    log.info("Capture started on %s", interface)
    log.warning("Malformed packet: %s", e)
    log.error("Database error: %s", e, exc_info=True)
"""

import logging
import pathlib
import sys
from logging.handlers import RotatingFileHandler


# ── Log file location ─────────────────────────────────────────────────────────

def _log_file_path() -> pathlib.Path:
    """Store logs next to the exe when frozen, in project root otherwise."""
    if getattr(sys, "frozen", False):
        base = pathlib.Path(sys.executable).parent
    else:
        base = pathlib.Path(__file__).parent.parent
    log_dir = base / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "payloadcapture.log"


# ── Root logger setup ─────────────────────────────────────────────────────────

_configured = False

def _configure() -> None:
    global _configured
    if _configured:
        return

    root = logging.getLogger("pcs")   # "pcs" = PayloadCaptureSuite namespace
    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── Rotating file handler — 5 MB per file, 3 backups ─────────────────────
    try:
        fh = RotatingFileHandler(
            _log_file_path(),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except Exception:
        pass   # log file failure must never crash the application

    # ── Console handler — WARNING and above only ──────────────────────────────
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger namespaced under 'pcs.<name>'.

    Pass __name__ from the calling module:
        log = get_logger(__name__)
    """
    _configure()
    # Strip the leading project path so names are clean
    short = name.replace("PayloadCaptureSuite.", "").replace(".", "/")
    return logging.getLogger(f"pcs.{short}")


def set_level(level: str) -> None:
    """
    Change the log level at runtime (e.g. from Settings).
    level: "DEBUG" | "INFO" | "WARNING" | "ERROR"
    """
    _configure()
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.getLogger("pcs").setLevel(numeric)
