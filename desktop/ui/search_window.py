"""
ui/search_window.py

Global Investigation Search.

Searches across packets, flows, findings, notes, and timeline events
using SQLite queries — fast even for large sessions.

The analyst types a query (IP address, port, protocol, domain, keyword)
and immediately sees matching results from every data type, organised
into tabs so nothing is buried.
"""

import tkinter as tk
from tkinter import ttk

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT, BG_SELECTED,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
    SEVERITY_COLORS,
)
from ui.widgets import DarkButton, StatusBar, horizontal_separator, section_header
from evidence.database import global_search
from config.logger import get_logger

log = get_logger(__name__)


class SearchWindow:
    """
    Global search across all session data.

    Parameters
    ----------
    parent     : Tk root
    session_id : session to search within
    """

    def __init__(self, parent: tk.Tk, session_id: str):
        self.parent     = parent
        self.session_id = session_id
        self._last_query = ""

        self.window = tk.Toplevel(parent)
        self.window.title("Global Search")
        self.window.geometry("900x620")
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

        self._build_ui()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # Header
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        tk.Label(header, text="GLOBAL SEARCH", bg=BG_CARD,
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(side="left")
        tk.Label(header,
                 text="Search packets · flows · findings · notes · timeline",
                 bg=BG_CARD, fg=FG_SECONDARY, font=FONT_SMALL).pack(
                     side="left", padx=PAD_INNER)

        horizontal_separator(self.window).pack(fill="x")

        # Search bar
        bar = tk.Frame(self.window, bg=BG_DARK, pady=PAD_SMALL, padx=PAD_OUTER)
        bar.pack(fill="x")

        tk.Label(bar, text="SEARCH:", bg=BG_DARK, fg=FG_SECONDARY,
                 font=FONT_LABEL).pack(side="left")

        self._query_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self._query_var, width=50,
                          font=FONT_MONO)
        entry.pack(side="left", padx=PAD_SMALL)
        entry.bind("<Return>", lambda e: self._run_search())
        entry.focus_set()

        DarkButton(bar, "SEARCH", command=self._run_search,
                   accent=True).pack(side="left")
        DarkButton(bar, "CLEAR",
                   command=self._clear).pack(side="left", padx=PAD_SMALL)

        tk.Label(bar,
                 text="Enter IP, port, protocol, domain, keyword…",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL).pack(
                     side="left", padx=PAD_INNER)

        horizontal_separator(self.window).pack(fill="x")

        # Results notebook
        nb = ttk.Notebook(self.window)
        nb.pack(fill="both", expand=True, padx=PAD_SMALL, pady=PAD_SMALL)

        self._tabs: dict[str, ttk.Treeview] = {}

        tab_defs = [
            ("Packets",  ["#", "TIME", "PROTOCOL", "SRC", "DST", "PORTS", "RISK"],
             [55, 90, 75, 130, 130, 100, 65]),
            ("Flows",    ["PROTOCOL", "SRC", "DST", "PKTS", "BYTES", "RISK"],
             [75, 150, 150, 70, 80, 65]),
            ("Findings", ["SEV", "TITLE", "STATE"],
             [75, 320, 100]),
            ("Notes",    ["TIME", "TYPE", "CONTENT"],
             [90, 80, 380]),
            ("Timeline", ["TIME", "TYPE", "DESCRIPTION"],
             [80, 80, 400]),
        ]

        for tab_name, cols, widths in tab_defs:
            frame = tk.Frame(nb, bg=BG_DARK)
            nb.add(frame, text=f"  {tab_name}  ")

            tree = ttk.Treeview(frame, columns=cols, show="headings",
                                selectmode="browse")
            for col, w in zip(cols, widths):
                tree.heading(col, text=col, anchor="w")
                tree.column(col, width=w, minwidth=40, anchor="w")

            tree.tag_configure("even", background="#161b22")
            tree.tag_configure("odd",  background="#1c2128")
            for sev, color in SEVERITY_COLORS.items():
                tree.tag_configure(sev, foreground=color)

            scroll_y = ttk.Scrollbar(frame, orient="vertical",
                                     command=tree.yview)
            tree.configure(yscrollcommand=scroll_y.set)
            scroll_y.pack(side="right", fill="y")
            tree.pack(fill="both", expand=True)

            self._tabs[tab_name] = tree

        # Status bar
        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")
        self._status_bar.set_status("Enter a query and press Search or Enter",
                                    "idle")

    # ── Search ────────────────────────────────────────────────────────────────

    def _run_search(self) -> None:
        query = self._query_var.get().strip()
        if not query:
            return
        if query == self._last_query:
            return

        self._last_query = query
        self._clear_results()
        self._status_bar.set_status(f"Searching for '{query}'…", "active")
        self.window.update_idletasks()

        try:
            results = global_search(self.session_id, query)
        except Exception as e:
            log.error("Search error: %s", e, exc_info=True)
            self._status_bar.set_status(f"Search error: {e}", "error")
            return

        self._populate_packets(results["packets"])
        self._populate_flows(results["flows"])
        self._populate_findings(results["findings"])
        self._populate_notes(results["notes"])
        self._populate_timeline(results["timeline"])

        total = sum(
            len(results[k])
            for k in ("packets", "flows", "findings", "notes", "timeline")
        )
        self._status_bar.set_status(
            f"'{query}' — {total} results  "
            f"(packets: {len(results['packets'])}  "
            f"flows: {len(results['flows'])}  "
            f"findings: {len(results['findings'])})",
            "idle"
        )
        log.info("Search '%s' → %d total results", query, total)

    def _clear(self) -> None:
        self._query_var.set("")
        self._last_query = ""
        self._clear_results()
        self._status_bar.set_status("Ready", "idle")

    def _clear_results(self) -> None:
        for tree in self._tabs.values():
            tree.delete(*tree.get_children())

    # ── Result populators ─────────────────────────────────────────────────────

    def _populate_packets(self, packets: list[dict]) -> None:
        tree = self._tabs["Packets"]
        for i, p in enumerate(packets):
            src = f"{p.get('src_ip','?')}:{p.get('src_port','?')}"
            dst = f"{p.get('dst_ip','?')}:{p.get('dst_port','?')}"
            risk = p.get("risk_level", "NONE")
            tag  = risk if risk in SEVERITY_COLORS else ("even" if i % 2 == 0 else "odd")
            tree.insert("", "end", values=(
                p.get("packet_number", ""),
                (p.get("capture_time") or "")[-12:-3],
                p.get("protocol", ""),
                src, dst, "", risk,
            ), tags=(tag,))

        if not packets:
            tree.insert("", "end", values=("", "(no matching packets)", "", "", "", "", ""))

    def _populate_flows(self, flows: list[dict]) -> None:
        tree = self._tabs["Flows"]
        for i, f in enumerate(flows):
            from evidence.sessions import format_bytes
            src = f"{f.get('src_ip','?')}:{f.get('src_port','?')}"
            dst = f"{f.get('dst_ip','?')}:{f.get('dst_port','?')}"
            risk = f.get("risk_level", "NONE")
            tag  = risk if risk in SEVERITY_COLORS else ("even" if i % 2 == 0 else "odd")
            tree.insert("", "end", values=(
                f.get("protocol", ""),
                src, dst,
                f"{f.get('packet_count', 0):,}",
                format_bytes(f.get("byte_count", 0)),
                risk,
            ), tags=(tag,))

        if not flows:
            tree.insert("", "end", values=("", "(no matching flows)", "", "", "", ""))

    def _populate_findings(self, findings: list[dict]) -> None:
        tree = self._tabs["Findings"]
        for i, f in enumerate(findings):
            sev  = f.get("severity", "INFO")
            tag  = sev
            tree.insert("", "end", values=(
                sev,
                f.get("title", ""),
                f.get("state", "NEW"),
            ), tags=(tag,))

        if not findings:
            tree.insert("", "end", values=("", "(no matching findings)", ""))

    def _populate_notes(self, notes: list[dict]) -> None:
        tree = self._tabs["Notes"]
        for i, n in enumerate(notes):
            tag = "even" if i % 2 == 0 else "odd"
            tree.insert("", "end", values=(
                (n.get("created_at") or "")[-8:],
                n.get("target_type", ""),
                (n.get("content") or "")[:120],
            ), tags=(tag,))

        if not notes:
            tree.insert("", "end", values=("", "", "(no matching notes)"))

    def _populate_timeline(self, events: list[dict]) -> None:
        tree = self._tabs["Timeline"]
        for i, ev in enumerate(events):
            tag = "even" if i % 2 == 0 else "odd"
            tree.insert("", "end", values=(
                (ev.get("event_time") or "")[-8:],
                ev.get("event_type", ""),
                (ev.get("description") or "")[:100],
            ), tags=(tag,))

        if not events:
            tree.insert("", "end", values=("", "", "(no matching timeline events)"))
