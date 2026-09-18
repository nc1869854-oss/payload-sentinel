"""
ui/audit_window.py

Investigation Audit Trail window.

Shows every significant action taken during an investigation in
chronological order so analysts can reconstruct how a session evolved.

Recorded actions include:
    SESSION_CREATED      SESSION_CLOSED
    CAPTURE_STARTED      CAPTURE_STOPPED
    FINDING_CONFIRMED    FINDING_DISMISSED    FINDING_RESOLVED
    NOTE_ADDED           EVIDENCE_EXPORTED
    FIREWALL_BLOCK       FIREWALL_UNBLOCK
    REPORT_GENERATED     PCAP_IMPORTED
    ...and any action logged via db.log_action()

This window is read-only — it is a record, not an editor.
"""

import tkinter as tk
from tkinter import ttk, filedialog
import csv

from config.theme import (
    BG_DARK, BG_CARD, FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_WARNING, FG_MUTED,
    FONT_CARD_TITLE, FONT_SMALL, PAD_OUTER, PAD_INNER, PAD_SMALL,
)
from ui.widgets import DarkButton, StatusBar, horizontal_separator
from evidence.database import get_action_log
from config.logger import get_logger

log = get_logger(__name__)

# Action categories → colour
ACTION_COLORS = {
    "SESSION":  FG_ACCENT,
    "CAPTURE":  FG_SUCCESS,
    "FINDING":  FG_WARNING,
    "NOTE":     FG_PRIMARY,
    "EVIDENCE": "#d2a8ff",
    "FIREWALL": "#f85149",
    "REPORT":   "#79c0ff",
    "PCAP":     "#58a6ff",
}


def _action_color(action: str) -> str:
    """Return a colour based on the action prefix."""
    for prefix, color in ACTION_COLORS.items():
        if action.upper().startswith(prefix):
            return color
    return FG_SECONDARY


class AuditWindow:
    """
    Investigation Audit Trail.

    Parameters
    ----------
    parent     : Tk root window
    session_id : session to show the trail for
    """

    def __init__(self, parent: tk.Tk, session_id: str):
        self.parent     = parent
        self.session_id = session_id

        self.window = tk.Toplevel(parent)
        self.window.title(f"Audit Trail — {session_id}")
        self.window.geometry("860x520")
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

        self._build_ui()
        self._load()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        header = tk.Frame(self.window, bg=BG_CARD,
                          pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        tk.Label(header, text="INVESTIGATION AUDIT TRAIL",
                 bg=BG_CARD, fg=FG_ACCENT,
                 font=FONT_CARD_TITLE).pack(side="left")
        tk.Label(header, text=self.session_id,
                 bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(side="left", padx=PAD_INNER)

        right = tk.Frame(header, bg=BG_CARD)
        right.pack(side="right")
        DarkButton(right, "REFRESH", command=self._load).pack(side="right",
                                                               padx=2)
        DarkButton(right, "EXPORT CSV",
                   command=self._export_csv).pack(side="right", padx=2)

        horizontal_separator(self.window).pack(fill="x")

        tk.Label(
            self.window,
            text="Read-only record of all analyst actions in this session.",
            bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL, anchor="w"
        ).pack(fill="x", padx=PAD_OUTER, pady=(PAD_SMALL, 0))

        # Table
        frame = tk.Frame(self.window, bg=BG_DARK)
        frame.pack(fill="both", expand=True,
                   padx=PAD_OUTER, pady=PAD_SMALL)

        cols = ("TIME", "ACTION", "DETAIL")
        self._tree = ttk.Treeview(
            frame, columns=cols, show="headings", selectmode="browse"
        )
        self._tree.heading("TIME",   text="TIME",   anchor="w")
        self._tree.heading("ACTION", text="ACTION", anchor="w")
        self._tree.heading("DETAIL", text="DETAIL", anchor="w")
        self._tree.column("TIME",   width=85,  anchor="w")
        self._tree.column("ACTION", width=180, anchor="w")
        self._tree.column("DETAIL", width=450, anchor="w")

        # Per-category colour tags
        for prefix, color in ACTION_COLORS.items():
            self._tree.tag_configure(prefix, foreground=color)
        self._tree.tag_configure("even", background="#161b22")
        self._tree.tag_configure("odd",  background="#1c2128")

        scroll_y = ttk.Scrollbar(frame, orient="vertical",
                                  command=self._tree.yview)
        self._tree.configure(yscrollcommand=scroll_y.set)
        scroll_y.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

    # ── Data ─────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        self._tree.delete(*self._tree.get_children())

        try:
            entries = get_action_log(self.session_id)
        except Exception as e:
            log.error("Could not load action log: %s", e)
            self._status_bar.set_status(f"Error: {e}", "error")
            return

        if not entries:
            self._tree.insert("", "end", values=(
                "", "", "(no actions recorded for this session yet)"
            ))
            self._status_bar.set_status("No audit entries", "idle")
            return

        for i, entry in enumerate(entries):
            action = entry.get("action", "")
            # Determine colour tag from action prefix
            color_tag = "even"
            for prefix in ACTION_COLORS:
                if action.upper().startswith(prefix):
                    color_tag = prefix
                    break

            row_tag = color_tag if color_tag in ACTION_COLORS else \
                      ("even" if i % 2 == 0 else "odd")

            time_str = (entry.get("logged_at") or "")[-8:]   # HH:MM:SS

            self._tree.insert("", "end", values=(
                time_str,
                action,
                entry.get("detail") or "",
            ), tags=(row_tag,))

        self._status_bar.set_status(
            f"{len(entries):,} audit entries", "idle")
        # Scroll to latest
        children = self._tree.get_children()
        if children:
            self._tree.see(children[-1])

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export Audit Trail",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"audit_{self.session_id}.csv",
            parent=self.window,
        )
        if not path:
            return

        try:
            entries = get_action_log(self.session_id)
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["id", "session_id", "logged_at",
                                   "action", "detail"])
                writer.writeheader()
                writer.writerows(entries)

            self._status_bar.set_status(f"Exported to {path}", "idle")
        except Exception as e:
            log.error("Audit export failed: %s", e)
            from tkinter import messagebox
            messagebox.showerror("Export Error", str(e), parent=self.window)
