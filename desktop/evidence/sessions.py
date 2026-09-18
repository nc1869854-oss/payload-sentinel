"""
evidence/sessions.py

Session lifecycle management for Payload Capture Suite.

A "session" is one investigation unit — it groups packets, flows,
alerts, and findings collected during a single monitoring period.
"""

import datetime


def generate_session_id() -> str:
    """
    Create a human-readable session ID based on date and time.

    Example:  20260906-143215
              YYYYMMDD-HHMMSS
    """
    now = datetime.datetime.now()
    return now.strftime("%Y%m%d-%H%M%S")


def format_duration(start_time: datetime.datetime, end_time: datetime.datetime = None) -> str:
    """
    Return a human-readable duration string HH:MM:SS.

    If end_time is None, uses the current time (for live sessions).
    """
    if end_time is None:
        end_time = datetime.datetime.now()

    delta = end_time - start_time
    total_seconds = int(delta.total_seconds())

    hours   = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def format_bytes(byte_count: int) -> str:
    """
    Convert a raw byte count into a readable string.

    Examples:
        1023         → "1023 B"
        1024         → "1.0 KB"
        1_048_576    → "1.0 MB"
        1_073_741_824→ "1.0 GB"
    """
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024 ** 2:
        return f"{byte_count / 1024:.1f} KB"
    elif byte_count < 1024 ** 3:
        return f"{byte_count / (1024 ** 2):.1f} MB"
    else:
        return f"{byte_count / (1024 ** 3):.1f} GB"
