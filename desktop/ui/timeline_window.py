"""
ui/timeline_window.py

Investigation Timeline window.

Displays network events in chronological order so analysts can
reconstruct the sequence of what happened:

    15:41:52  DNS query  →  example.com
    15:41:53  DNS response  ←  93.184.216.34
    15:41:55  TCP connection  →  93.184.216.34:443 (TLS/HTTPS expected)
    15:41:56  TCP connection  →  142.250.80.46:443 (TLS/HTTPS expected)
    ...

Clicking any event will highlight its related packet/flow.
"""

import tkinter as tk
from tkinter import ttk

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT, BG_SELECTED,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_WARNING, FG_DANGER,
    FG_INFO, FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
    TIMELINE_WINDOW_SIZE,
)
from ui.widgets import DarkButton, StatusBar, horizontal_separator, section_header
from investigation.timeline import (
    build_timeline_events, filter_events,
    EVENT_TYPE_DNS, EVENT_TYPE_TCP, EVENT_TYPE_UDP,
    EVENT_TYPE_TLS, EVENT_TYPE_HTTP, EVENT_TYPE_ICMP, EVENT_TYPE_ALERT,
)


# Colour per event type — makes the timeline scannable at a glance
EVENT_COLORS = {
    EVENT_TYPE_DNS:     "#79c0ff",   # blue
    EVENT_TYPE_TCP:     "#3fb950",   # green
    EVENT_TYPE_UDP:     "#58a6ff",   # lighter blue
    EVENT_TYPE_TLS:     "#d2a8ff",   # purple
    EVENT_TYPE_HTTP:    "#ffa657",   # orange
    EVENT_TYPE_ICMP:    "#f85149",   # red
    EVENT_TYPE_ALERT:   "#f85149",   # red
    "GENERAL":          "#8b949e",   # grey
    "FLOW":             "#3fb950",
}


class TimelineWindow:
    """
    Chronological investigation timeline.

    Parameters
    ----------
    parent     : Tk root window
    session_id : active session ID
    packets    : list of parsed packet dicts
    """

    def __init__(self, parent: tk.Tk, session_id: str, packets: list[dict]):
        self.parent     = parent
        self.session_id = session_id
        self._packets   = packets

        # Build all events once; filter is applied without rebuilding
        self._all_events = build_timeline_events(packets)
        self._active_filter = "ALL"

        self.window = tk.Toplevel(parent)
        self.window.title("Investigation Timeline")
        self.window.geometry(TIMELINE_WINDOW_SIZE)
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

        self._build_ui()
        self._populate_timeline()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        horizontal_separator(self.window).pack(fill="x")

        body = tk.Frame(self.window, bg=BG_DARK)
        body.pack(fill="both", expand=True)

        self._build_timeline_list(body)
        self._build_detail_panel(body)

        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

    def _build_header(self) -> None:
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        left = tk.Frame(header, bg=BG_CARD)
        left.pack(side="left")

        tk.Label(left, text="INVESTIGATION TIMELINE", bg=BG_CARD,
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(left, text="Network events reconstructed in chronological order",
                 bg=BG_CARD, fg=FG_SECONDARY, font=FONT_SMALL).pack(anchor="w")

        # Type filter buttons
        filter_row = tk.Frame(header, bg=BG_CARD)
        filter_row.pack(fill="x", pady=(PAD_SMALL, 0))

        tk.Label(filter_row, text="SHOW:", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_LABEL).pack(side="left")

        self._filter_buttons: dict[str, tk.Button] = {}

        filter_types = ["ALL", "DNS", "TCP", "UDP", "TLS", "HTTP", "ICMP", "ALERT"]
        for ft in filter_types:
            btn = tk.Button(
                filter_row, text=ft, bg=BG_CARD, fg=FG_SECONDARY,
                font=FONT_SMALL, relief="flat", bd=0, cursor="hand2",
                padx=8, pady=2,
                command=lambda t=ft: self._set_filter(t)
            )
            btn.pack(side="left", padx=1)
            self._filter_buttons[ft] = btn

        # Highlight the active filter button
        self._update_filter_buttons()

        # IP search
        ip_row = tk.Frame(header, bg=BG_CARD)
        ip_row.pack(fill="x", pady=(4, 0))

        tk.Label(ip_row, text="IP:", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_LABEL).pack(side="left")

        self._ip_filter_var = tk.StringVar()
        self._ip_filter_var.trace_add("write", lambda *_: self._populate_timeline())
        ttk.Entry(ip_row, textvariable=self._ip_filter_var,
                  width=20).pack(side="left", padx=PAD_SMALL)

        DarkButton(ip_row, "CLEAR",
                   command=lambda: self._ip_filter_var.set("")
                   ).pack(side="left")

    def _build_timeline_list(self, parent: tk.Frame) -> None:
        """The main scrollable event list on the left."""
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(side="left", fill="both", expand=True)

        # Column headers
        cols = ("TIME", "TYPE", "DESCRIPTION", "IP")
        col_widths = {
            "TIME": 80, "TYPE": 70, "DESCRIPTION": 350, "IP": 130,
        }

        self._timeline_tree = ttk.Treeview(
            frame, columns=cols, show="headings", selectmode="browse"
        )
        for col in cols:
            self._timeline_tree.heading(col, text=col, anchor="w")
            self._timeline_tree.column(col, width=col_widths.get(col, 100),
                                        minwidth=40, anchor="w")

        # Tag per event type for colour coding
        for etype, color in EVENT_COLORS.items():
            self._timeline_tree.tag_configure(etype, foreground=color)

        self._timeline_tree.tag_configure("even", background="#161b22")
        self._timeline_tree.tag_configure("odd",  background="#1c2128")

        scroll_y = ttk.Scrollbar(frame, orient="vertical",
                                  command=self._timeline_tree.yview)
        self._timeline_tree.configure(yscrollcommand=scroll_y.set)

        scroll_y.pack(side="right", fill="y")
        self._timeline_tree.pack(fill="both", expand=True)

        self._timeline_tree.bind("<<TreeviewSelect>>", self._on_event_selected)

    def _build_detail_panel(self, parent: tk.Frame) -> None:
        """Right panel showing details of the selected event."""
        panel = tk.Frame(parent, bg=BG_CARD, width=280)
        panel.pack(side="right", fill="y")
        panel.pack_propagate(False)

        info = tk.Frame(panel, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        info.pack(fill="x")

        section_header(info, "EVENT DETAILS", bg=BG_CARD).pack(anchor="w",
                                                                  pady=(0, PAD_SMALL))

        self._event_time_label = tk.Label(
            info, text="Time: —", bg=BG_CARD, fg=FG_PRIMARY, font=FONT_MONO,
            anchor="w"
        )
        self._event_time_label.pack(fill="x")

        self._event_type_label = tk.Label(
            info, text="Type: —", bg=BG_CARD, fg=FG_SECONDARY, font=FONT_BODY,
            anchor="w"
        )
        self._event_type_label.pack(fill="x")

        self._event_desc_label = tk.Label(
            info, text="—", bg=BG_CARD, fg=FG_PRIMARY, font=FONT_BODY,
            wraplength=240, justify="left", anchor="w"
        )
        self._event_desc_label.pack(fill="x", pady=(PAD_SMALL, 0))

        horizontal_separator(panel, bg=BG_CARD).pack(fill="x", pady=PAD_SMALL)

        # Related info
        rel_frame = tk.Frame(panel, bg=BG_CARD, padx=PAD_INNER)
        rel_frame.pack(fill="x")

        section_header(rel_frame, "RELATED", bg=BG_CARD).pack(anchor="w",
                                                                pady=(0, PAD_SMALL))

        self._rel_ip_label = tk.Label(
            rel_frame, text="IP: —", bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_SMALL, anchor="w"
        )
        self._rel_ip_label.pack(fill="x")

        self._rel_pkt_label = tk.Label(
            rel_frame, text="Packet: —", bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_SMALL, anchor="w"
        )
        self._rel_pkt_label.pack(fill="x")

        self._rel_flow_label = tk.Label(
            rel_frame, text="Flow: —", bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_SMALL, wraplength=240, justify="left", anchor="w"
        )
        self._rel_flow_label.pack(fill="x")

        horizontal_separator(panel, bg=BG_CARD).pack(fill="x", pady=PAD_SMALL)

        # Statistics summary
        stats_frame = tk.Frame(panel, bg=BG_CARD, padx=PAD_INNER)
        stats_frame.pack(fill="x")

        section_header(stats_frame, "SESSION TOTALS", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        self._total_events_label = tk.Label(
            stats_frame, text="Events: —", bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_SMALL, anchor="w"
        )
        self._total_events_label.pack(fill="x")

        self._dns_count_label = tk.Label(
            stats_frame, text="DNS: —", bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_SMALL, anchor="w"
        )
        self._dns_count_label.pack(fill="x")

        self._tcp_count_label = tk.Label(
            stats_frame, text="TCP: —", bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_SMALL, anchor="w"
        )
        self._tcp_count_label.pack(fill="x")

    # ── Data Population ───────────────────────────────────────────────────────

    def _populate_timeline(self) -> None:
        """Fill the timeline list with filtered events."""
        self._timeline_tree.delete(*self._timeline_tree.get_children())

        # Type filter
        events = filter_events(self._all_events, self._active_filter)

        # IP filter
        ip_text = self._ip_filter_var.get().strip()
        if ip_text:
            events = [
                e for e in events
                if ip_text in (e.get("related_ip") or "")
                or ip_text in (e.get("description") or "")
            ]

        for i, event in enumerate(events):
            tag = event.get("event_type", "GENERAL")
            row_tag = "even" if i % 2 == 0 else "odd"

            self._timeline_tree.insert(
                "", "end", iid=str(i),
                values=(
                    event["display_time"],
                    event["event_type"],
                    event["description"],
                    event.get("related_ip") or "—",
                ),
                tags=(tag, row_tag),
            )

        # Update summary stats
        all_events = self._all_events
        dns_count  = sum(1 for e in all_events if e["event_type"] == EVENT_TYPE_DNS)
        tcp_count  = sum(1 for e in all_events
                         if e["event_type"] in (EVENT_TYPE_TCP, EVENT_TYPE_TLS))

        self._total_events_label.configure(text=f"Events: {len(all_events):,}")
        self._dns_count_label.configure(  text=f"DNS: {dns_count:,}")
        self._tcp_count_label.configure(  text=f"TCP/TLS: {tcp_count:,}")

        self._status_bar.set_status(
            f"Showing {len(events):,} of {len(all_events):,} events  "
            f"(filter: {self._active_filter})",
            "idle"
        )

    def _on_event_selected(self, event) -> None:
        """Show details for the selected timeline event."""
        sel = self._timeline_tree.selection()
        if not sel:
            return

        idx = int(sel[0])

        # Rebuild filtered list to match table order
        events = filter_events(self._all_events, self._active_filter)
        ip_text = self._ip_filter_var.get().strip()
        if ip_text:
            events = [e for e in events
                      if ip_text in (e.get("related_ip") or "")
                      or ip_text in (e.get("description") or "")]

        if idx >= len(events):
            return

        ev = events[idx]

        etype_color = EVENT_COLORS.get(ev.get("event_type", ""), FG_SECONDARY)

        self._event_time_label.configure(text=f"Time: {ev['display_time']}")
        self._event_type_label.configure(
            text=f"Type: {ev['event_type']}", fg=etype_color
        )
        self._event_desc_label.configure(text=ev["description"])

        self._rel_ip_label.configure(
            text=f"IP: {ev.get('related_ip') or '—'}"
        )
        self._rel_pkt_label.configure(
            text=f"Packet #: {ev.get('related_packet') or '—'}"
        )
        flow_display = (ev.get("related_flow") or "—")[:40]
        self._rel_flow_label.configure(text=f"Flow: {flow_display}")

    # ── Filter Controls ───────────────────────────────────────────────────────

    def _set_filter(self, event_type: str) -> None:
        self._active_filter = event_type
        self._update_filter_buttons()
        self._populate_timeline()

    def _update_filter_buttons(self) -> None:
        """Highlight the active filter button, dim the others."""
        for ft, btn in self._filter_buttons.items():
            if ft == self._active_filter:
                btn.configure(bg=BG_SELECTED, fg=FG_PRIMARY)
            else:
                btn.configure(bg=BG_CARD, fg=FG_SECONDARY)
