"""
main.py

Payload Capture Suite — application entry point.

Run:
    python main.py

Requirements:
    pip install -r requirements.txt

On Windows, install Npcap for live capture:
    https://npcap.com
"""

import sys
import pathlib
import tkinter as tk
from tkinter import messagebox

# ── Path setup ────────────────────────────────────────────────────────────────
PROJECT_ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# ── Logging (must be first) ───────────────────────────────────────────────────
from config.logger import get_logger
log = get_logger("main")


def main() -> None:
    log.info("Payload Capture Suite starting")

    # ── Load settings ─────────────────────────────────────────────────────────
    import config.settings as settings
    settings.load()

    # ── Run startup checks ────────────────────────────────────────────────────
    from core.startup import run_startup_checks
    result = run_startup_checks()

    # Fatal errors prevent the app from opening
    if result.errors:
        root = tk.Tk()
        root.withdraw()
        error_text = "\n\n".join(result.errors)
        messagebox.showerror(
            "Payload Capture Suite — Startup Error",
            f"The application cannot start:\n\n{error_text}\n\n"
            "See logs/ for details."
        )
        log.critical("Startup aborted: %s", result.errors)
        sys.exit(1)

    # ── Create root window ────────────────────────────────────────────────────
    root = tk.Tk()
    root.withdraw()   # hide while loading

    # Set icon
    icon_path = PROJECT_ROOT / "assets" / "icons" / "icon.ico"
    if icon_path.exists():
        try:
            root.iconbitmap(str(icon_path))
        except Exception:
            pass

    # ── Build main window ─────────────────────────────────────────────────────
    from ui.main_window import MainWindow
    app = MainWindow(root)

    # ── Show startup dialog if there are warnings ──────────────────────────────
    if result.warnings:
        from ui.startup_dialog import StartupDialog
        def show_main():
            root.deiconify()
            root.lift()
        StartupDialog(root, result, on_continue=show_main)
    else:
        root.deiconify()
        root.lift()

    # ── Graceful exit ─────────────────────────────────────────────────────────
    # MainWindow registers its own WM_DELETE_WINDOW handler (_on_close) that
    # stops any running capture, closes the session and saves settings before
    # destroying the root.  We only need a fallback here in case the window
    # was never created (e.g. a startup error path).
    root.mainloop()
    log.info("Application exited cleanly")


if __name__ == "__main__":
    main()
