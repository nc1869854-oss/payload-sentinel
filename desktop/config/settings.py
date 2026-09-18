"""
config/settings.py

Application settings — loaded at startup, saved when the user changes them.
Stored as JSON in the user's home directory so they survive reinstalls.
"""

import json
import pathlib

# Path to the settings file (next to the project data folder works too)
import sys as _sys

def _settings_path() -> pathlib.Path:
    """Settings file lives in AppData when compiled, home dir from source."""
    if getattr(_sys, "frozen", False):
        import os
        appdata = os.environ.get("APPDATA", str(pathlib.Path.home()))
        return pathlib.Path(appdata) / "PayloadCaptureSuite" / "settings.json"
    return pathlib.Path.home() / ".payloadcapturesuite" / "settings.json"

SETTINGS_FILE = _settings_path()

# ─── Default Values ──────────────────────────────────────────────────────────

DEFAULTS = {
    # Capture
    "default_interface": "",        # empty = let the user choose
    "max_visible_packets": 5000,    # rows kept in the live table
    "payload_preview_bytes": 512,   # bytes shown in ASCII/HEX panel
    "capture_buffer_size": 65535,

    # Analysis
    "enable_dns_analysis": True,
    "enable_flow_tracking": True,
    "enable_anomaly_rules": True,
    "risk_threshold": "LOW",        # minimum severity to display

    # Reports
    "export_directory": str(pathlib.Path.home() / "PayloadCaptureExports"),
    "include_payload_stats": True,
    "include_analyst_notes": True,

    # Firewall
    "enable_firewall_controls": False,   # opt-in only
}


# ─── In-memory settings store ────────────────────────────────────────────────

_settings: dict = {}


def load() -> dict:
    """
    Load settings from disk.
    Falls back to defaults for any missing key so the app always has values.
    """
    global _settings
    _settings = dict(DEFAULTS)   # start with a full copy of defaults

    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            # Only keep keys we recognise (ignore stale keys from old versions)
            for key in DEFAULTS:
                if key in saved:
                    _settings[key] = saved[key]
        except Exception:
            pass   # corrupted file — just use defaults

    return _settings


def save() -> None:
    """Write current settings to disk."""
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(_settings, f, indent=2)
    except Exception as e:
        print(f"[Settings] Could not save settings: {e}")


def get(key: str, default=None):
    """Return a single setting value."""
    return _settings.get(key, default)


def set_value(key: str, value) -> None:
    """Update a setting in memory (call save() to persist)."""
    _settings[key] = value
