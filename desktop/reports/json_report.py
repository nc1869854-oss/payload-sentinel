"""
reports/json_report.py

Export the complete report data as a structured JSON file.

The JSON export is the most complete format — it includes every field
from the report_data dict and is suitable for:
  - Archiving investigation data
  - Importing into other analysis tools
  - Automated processing and correlation
  - Long-term evidence storage
"""

import json
import pathlib
import datetime


def generate_json_export(report_data: dict,
                         output_path: str | pathlib.Path) -> str:
    """
    Write a formatted JSON file containing the complete report data.
    Returns the absolute path as a string.
    """
    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Build an exportable version (strip any non-serialisable objects)
    exportable = _prepare_for_json(report_data)

    with open(str(path), "w", encoding="utf-8") as f:
        json.dump(exportable, f, indent=2, ensure_ascii=False,
                  default=_json_default)

    return str(path)


def _prepare_for_json(data) -> dict:
    """
    Recursively walk the report data and ensure everything is JSON-safe.

    sqlite3.Row objects (returned from DB) need to be converted to dicts.
    """
    if isinstance(data, dict):
        return {k: _prepare_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_prepare_for_json(item) for item in data]
    elif hasattr(data, "keys"):
        # sqlite3.Row or similar mapping
        return {k: _prepare_for_json(data[k]) for k in data.keys()}
    else:
        return data


def _json_default(obj):
    """Fallback serialiser for types json.dump cannot handle."""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    return str(obj)
