"""
ui/stats_window.py

Statistics window — a Toplevel that wraps the StatsPanel.

Opened from the Capture window toolbar.
Can also be opened standalone from the main dashboard.
"""

import tkinter as tk

from config.theme import BG_DARK, FG_ACCENT, FG_SECONDARY, FONT_CARD_TITLE, FONT_SMALL
from ui.widgets import DarkButton, StatusBar, horizontal_separator
from ui.stats_panel import StatsPanel


class StatsWindow:
    """
    Statistics window for a capture session.

    Parameters
    ----------
    parent     : parent Tk window
    session_id : session being analysed
    packets    : list of parsed packet dicts
    flows      : list of flow dicts
    """

    def __init__(self, parent, session_id: str,
                 packets: list[dict], flows: list[dict]):
        self.parent     = parent
        self.session_id = session_id
        self._packets   = packets
        self._flows     = flows

        self.window = tk.Toplevel(parent)
        self.window.title(f"Session Statistics — {session_id}")
        self.window.geometry("700x700")
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

        self._build_ui()

    def _build_ui(self) -> None:
        # Header
        header = tk.Frame(self.window, bg="#161b22", pady=8, padx=16)
        header.pack(fill="x")
        tk.Label(header, text="SESSION STATISTICS", bg="#161b22",
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(side="left")
        tk.Label(header, text=self.session_id, bg="#161b22",
                 fg=FG_SECONDARY, font=FONT_SMALL).pack(side="left", padx=8)

        DarkButton(header, "REFRESH", command=self._refresh
                   ).pack(side="right")

        horizontal_separator(self.window).pack(fill="x")

        # Stats panel fills the rest of the window
        self._stats_panel = StatsPanel(self.window)
        self._stats_panel.pack(fill="both", expand=True)

        # Status bar
        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

        # Initial population
        self._refresh()

    def _refresh(self) -> None:
        """Recalculate and redisplay all statistics."""
        self._stats_panel.refresh(self._packets, self._flows)
        self._status_bar.set_status(
            f"Packets: {len(self._packets):,}   Flows: {len(self._flows):,}", "idle"
        )
