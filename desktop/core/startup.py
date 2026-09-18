"""
core/startup.py

Startup health checks for Payload Capture Suite.

Runs before the UI opens and produces a human-readable report
of what is available, what is missing, and what can still work.

The application will still launch even if Scapy or Npcap is missing
— those features are simply disabled with a clear message.
"""

import sys
import pathlib
from dataclasses import dataclass, field
from config.logger import get_logger

log = get_logger(__name__)


@dataclass
class StartupResult:
    ok: bool = True
    checks: list = field(default_factory=list)   # list of (name, ok, message)
    warnings: list = field(default_factory=list)
    errors: list   = field(default_factory=list)

    def add(self, name: str, passed: bool, message: str) -> None:
        self.checks.append((name, passed, message))
        if not passed:
            self.warnings.append(f"{name}: {message}")
            log.warning("Startup check FAILED: %s — %s", name, message)
        else:
            log.info("Startup check OK: %s", name)

    def add_error(self, name: str, message: str) -> None:
        self.ok = False
        self.errors.append(f"{name}: {message}")
        self.checks.append((name, False, message))
        log.error("Startup check ERROR: %s — %s", name, message)


def run_startup_checks() -> StartupResult:
    result = StartupResult()

    # ── Python version ────────────────────────────────────────────────────────
    major, minor = sys.version_info[:2]
    if major >= 3 and minor >= 10:
        result.add("Python version",
                   True, f"{major}.{minor} ✓")
    else:
        result.add_error("Python version",
                         f"{major}.{minor} — Python 3.10+ required.")

    # ── Tkinter ───────────────────────────────────────────────────────────────
    try:
        import tkinter
        result.add("Tkinter", True, "available ✓")
    except ImportError:
        result.add_error("Tkinter",
                         "Not found. Install python3-tk (Linux) or use the "
                         "official Python installer (Windows/macOS).")

    # ── SQLite ────────────────────────────────────────────────────────────────
    try:
        import sqlite3
        result.add("SQLite", True, f"version {sqlite3.sqlite_version} ✓")
    except ImportError:
        result.add_error("SQLite", "Not available — database will not work.")

    # ── Scapy ─────────────────────────────────────────────────────────────────
    try:
        import scapy
        result.add("Scapy", True,
                   f"version {scapy.__version__} ✓")
    except ImportError:
        result.add("Scapy", False,
                   "Not installed — live capture and PCAP import unavailable.\n"
                   "Install with: pip install scapy")

    # ── Npcap / WinPcap (Windows only) ───────────────────────────────────────
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Npcap")
            winreg.CloseKey(key)
            result.add("Npcap", True, "installed ✓")
        except (ImportError, FileNotFoundError, OSError):
            result.add("Npcap", False,
                       "Not detected — live packet capture will not work.\n"
                       "Download from: https://npcap.com")
    else:
        result.add("Npcap", True,
                   "not required on this platform ✓")

    # ── ReportLab ─────────────────────────────────────────────────────────────
    try:
        import reportlab
        result.add("ReportLab", True,
                   f"version {reportlab.Version} ✓")
    except ImportError:
        result.add("ReportLab", False,
                   "Not installed — PDF report generation unavailable.\n"
                   "Install with: pip install reportlab")

    # ── Database directory ────────────────────────────────────────────────────
    try:
        from evidence.database import DB_PATH
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        result.add("Database directory",
                   True, f"{DB_PATH.parent} ✓")
    except Exception as e:
        result.add_error("Database directory",
                         f"Cannot create data directory: {e}")

    # ── Database initialisation ────────────────────────────────────────────────
    try:
        from evidence.database import initialise_database
        initialise_database()
        result.add("Database", True, "schema OK ✓")
    except Exception as e:
        result.add_error("Database", f"Initialisation failed: {e}")

    # ── Exports directory ─────────────────────────────────────────────────────
    try:
        import config.settings as settings
        export_dir = pathlib.Path(
            settings.get("export_directory",
                         str(pathlib.Path.home() / "PayloadCaptureExports"))
        )
        export_dir.mkdir(parents=True, exist_ok=True)
        result.add("Exports directory", True, f"{export_dir} ✓")
    except Exception as e:
        result.add("Exports directory", False,
                   f"Could not create: {e}")

    return result
