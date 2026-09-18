# PayloadCaptureSuite.spec
#
# PyInstaller build specification.
#
# Usage (run from the PayloadCaptureSuite project root):
#
#   pip install pyinstaller
#   pyinstaller PayloadCaptureSuite.spec
#
# The finished installer-ready exe appears at:
#   dist/PayloadCaptureSuite/PayloadCaptureSuite.exe
#
# Use --onedir (not --onefile) so Npcap drivers load correctly from
# the filesystem and ReportLab fonts are findable at runtime.

import sys
import os
from pathlib import Path

# ── Collect all Scapy data files (protocol definitions, etc.) ─────────────────
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

scapy_datas   = collect_data_files("scapy")
scapy_hiddens = collect_submodules("scapy")

# ReportLab fonts and data files
try:
    reportlab_datas   = collect_data_files("reportlab")
    reportlab_hiddens = collect_submodules("reportlab")
except Exception:
    reportlab_datas   = []
    reportlab_hiddens = []

# ── Analysis block ────────────────────────────────────────────────────────────
a = Analysis(
    ["main.py"],                        # entry point
    pathex=["."],                       # project root on the path
    binaries=[],
    datas=[
        # All Scapy protocol data
        *scapy_datas,
        # All ReportLab fonts and data
        *reportlab_datas,
        # Application assets (icons etc.) — create this folder if it doesn't exist
        ("assets", "assets"),
    ],
    hiddenimports=[
        # Scapy — imports modules dynamically by protocol name
        *scapy_hiddens,
        # ReportLab
        *reportlab_hiddens,
        # Tkinter is sometimes missed on certain Python builds
        "tkinter",
        "tkinter.ttk",
        "tkinter.messagebox",
        "tkinter.filedialog",
        # Standard library modules that may be missed
        "sqlite3",
        "ipaddress",
        "hashlib",
        "csv",
        "zipfile",
        "threading",
        "queue",
        "socket",
        "subprocess",
        "pathlib",
        "datetime",
        "json",
        "math",
        "collections",
        # Our own packages — PyInstaller finds them via Analysis but
        # listing them explicitly avoids missed-module warnings
        "config",
        "config.theme",
        "config.settings",
        "capture",
        "capture.engine",
        "capture.filters",
        "capture.pcap",
        "packets",
        "packets.parser",
        "packets.payload",
        "flows",
        "flows.tracker",
        "analysis",
        "analysis.rules",
        "analysis.statistics",
        "investigation",
        "investigation.ip",
        "investigation.timeline",
        "evidence",
        "evidence.database",
        "evidence.sessions",
        "evidence.hashing",
        "reports",
        "reports.report_builder",
        "reports.html_report",
        "reports.pdf_report",
        "reports.csv_report",
        "reports.json_report",
        "firewall",
        "firewall.windows_firewall",
        "ui",
        "ui.widgets",
        "ui.main_window",
        "ui.capture_window",
        "ui.flow_window",
        "ui.timeline_window",
        "ui.stats_panel",
        "ui.stats_window",
        "ui.alerts_window",
        "ui.ip_window",
        "ui.report_window",
        "ui.settings_window",
        "ui.firewall_dialog",
        "ui.pcap_window",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Things we definitely don't need — reduces exe size
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "PIL",
        "PyQt5",
        "PyQt6",
        "wx",
        "pytest",
        "IPython",
        "jupyter",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

# ── PYZ archive (pure-Python modules compressed) ─────────────────────────────
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

# ── EXE ──────────────────────────────────────────────────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,          # binaries go into the COLLECT step
    name="PayloadCaptureSuite",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,                       # compress with UPX if available
    console=False,                  # no console window (GUI app)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # UAC manifest — requests Administrator elevation at launch
    manifest="build/app.manifest",
    # Application icon — replace with your .ico file path
    icon="assets/icons/icon.ico" if os.path.exists("assets/icons/icon.ico") else None,
    # Version info shown in Windows file properties
    version=None,                   # set to a version_info.txt path if desired
)

# ── COLLECT — assembles the final dist folder ─────────────────────────────────
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="PayloadCaptureSuite",     # dist/PayloadCaptureSuite/
)
