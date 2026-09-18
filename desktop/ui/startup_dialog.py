"""
ui/startup_dialog.py

Startup health check dialog.

Shown at launch if any non-critical component is missing.
Critical failures (no database, no Python 3.10) prevent the app
from opening at all — those are handled in main.py.

For non-critical warnings (Scapy missing, Npcap missing, ReportLab
missing) this dialog lets the analyst know what won't work, then
lets them continue anyway.
"""

import tkinter as tk
from tkinter import ttk

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_WARNING, FG_DANGER,
    FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
)
from ui.widgets import DarkButton, horizontal_separator
from core.startup import StartupResult


class StartupDialog:
    """
    Non-blocking startup warning dialog.

    Only shown when there are non-fatal warnings.
    The user clicks CONTINUE to dismiss and open the main window.
    """

    def __init__(self, parent: tk.Tk, result: StartupResult,
                 on_continue=None):
        self._on_continue = on_continue

        win = tk.Toplevel(parent)
        win.title("Payload Capture Suite — Startup Check")
        win.geometry("580x420")
        win.configure(bg=BG_DARK)
        win.resizable(False, False)
        win.grab_set()
        win.protocol("WM_DELETE_WINDOW", self._continue)

        self._win = win
        self._build_ui(result)

    def _build_ui(self, result: StartupResult) -> None:
        # Header
        header = tk.Frame(self._win, bg=BG_CARD,
                          pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        tk.Label(header, text="PAYLOAD CAPTURE SUITE",
                 bg=BG_CARD, fg=FG_ACCENT,
                 font=FONT_CARD_TITLE).pack(side="left")

        sub = "● SYSTEM READY" if result.ok else "⚠ SOME FEATURES UNAVAILABLE"
        sub_color = FG_SUCCESS if result.ok else FG_WARNING
        tk.Label(header, text=sub, bg=BG_CARD, fg=sub_color,
                 font=FONT_BODY).pack(side="right")

        horizontal_separator(self._win).pack(fill="x")

        # Check list
        frame = tk.Frame(self._win, bg=BG_DARK,
                         padx=PAD_OUTER, pady=PAD_INNER)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="SYSTEM CHECK", bg=BG_DARK,
                 fg=FG_SECONDARY, font=FONT_LABEL).pack(anchor="w",
                                                         pady=(0, PAD_SMALL))

        for name, passed, message in result.checks:
            row = tk.Frame(frame, bg=BG_DARK)
            row.pack(fill="x", pady=2)

            indicator = "●" if passed else "⚠"
            color     = FG_SUCCESS if passed else FG_WARNING

            tk.Label(row, text=indicator, bg=BG_DARK, fg=color,
                     font=FONT_BODY, width=2).pack(side="left")

            tk.Label(row, text=name, bg=BG_DARK, fg=FG_PRIMARY,
                     font=FONT_BODY, width=22, anchor="w").pack(side="left")

            # First line of message only (keep it compact)
            short_msg = message.split("\n")[0]
            tk.Label(row, text=short_msg, bg=BG_DARK,
                     fg=FG_SECONDARY if passed else FG_WARNING,
                     font=FONT_SMALL, anchor="w").pack(
                         side="left", fill="x", expand=True)

        # Warning detail (only if warnings exist)
        if result.warnings:
            horizontal_separator(frame).pack(fill="x", pady=PAD_SMALL)
            tk.Label(frame,
                     text="Items marked ⚠ will not function until the missing "
                          "component is installed.\nThe application will open "
                          "normally — affected features will show clear messages.",
                     bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL,
                     wraplength=520, justify="left").pack(anchor="w")

        # Buttons
        horizontal_separator(self._win).pack(fill="x")
        btn_row = tk.Frame(self._win, bg=BG_DARK)
        btn_row.pack(fill="x", padx=PAD_OUTER, pady=PAD_INNER)

        DarkButton(btn_row, "CONTINUE",
                   command=self._continue, accent=True
                   ).pack(side="right")

        if result.warnings:
            tk.Label(btn_row,
                     text="Some features are limited — see above.",
                     bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL
                     ).pack(side="left")

    def _continue(self) -> None:
        if self._on_continue:
            self._on_continue()
        self._win.destroy()
