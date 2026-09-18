"""
ui/stats_panel.py

Statistics panel — can be embedded in any window as a tk.Frame.

Shows:
  • Protocol distribution (bar-style text chart)
  • Direction split (incoming / outgoing / internal)
  • Top source and destination IPs
  • Top ports

All rendering is plain Tkinter — no matplotlib dependency.
The bars are drawn with coloured Label widgets, which is lightweight
and doesn't require any extra packages.
"""

import tkinter as tk
from tkinter import ttk

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS,
    FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
)
from ui.widgets import section_header, horizontal_separator
from analysis.statistics import build_session_summary
from evidence.sessions import format_bytes


class StatsPanel(tk.Frame):
    """
    A self-contained statistics panel.

    Call refresh(packets, flows) whenever the data changes.

    Parameters
    ----------
    parent : parent widget
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG_DARK, **kwargs)
        self._build_ui()

    def _build_ui(self) -> None:
        # Scrollable container
        canvas = tk.Canvas(self, bg=BG_DARK, highlightthickness=0)
        scroll = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)

        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Inner frame that holds all the stat widgets
        self._inner = tk.Frame(canvas, bg=BG_DARK)
        self._inner_window = canvas.create_window(
            (0, 0), window=self._inner, anchor="nw"
        )

        def on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_configure(e):
            canvas.itemconfig(self._inner_window, width=e.width)

        self._inner.bind("<Configure>", on_frame_configure)
        canvas.bind("<Configure>", on_canvas_configure)

        # Mousewheel scrolling
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        self._build_sections()

    def _build_sections(self) -> None:
        """Build all statistic sections inside self._inner."""
        p = self._inner

        # ── Totals ────────────────────────────────────────────────────────────
        section_header(p, "SESSION TOTALS").pack(fill="x", padx=PAD_INNER,
                                                   pady=(PAD_INNER, PAD_TINY))

        totals_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_SMALL)
        totals_frame.pack(fill="x", padx=PAD_INNER)

        self._lbl_packets  = self._total_row(totals_frame, "Packets")
        self._lbl_bytes    = self._total_row(totals_frame, "Total Bytes")
        self._lbl_payload  = self._total_row(totals_frame, "Payload Bytes")
        self._lbl_flows    = self._total_row(totals_frame, "Flows")

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Direction ─────────────────────────────────────────────────────────
        section_header(p, "DIRECTION").pack(fill="x", padx=PAD_INNER, pady=PAD_TINY)

        dir_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_SMALL)
        dir_frame.pack(fill="x", padx=PAD_INNER)

        self._lbl_incoming  = self._total_row(dir_frame, "Incoming")
        self._lbl_outgoing  = self._total_row(dir_frame, "Outgoing")
        self._lbl_internal  = self._total_row(dir_frame, "Internal")
        self._lbl_unknown_d = self._total_row(dir_frame, "Unknown")

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Protocol Distribution ─────────────────────────────────────────────
        section_header(p, "PROTOCOL DISTRIBUTION").pack(fill="x", padx=PAD_INNER,
                                                          pady=PAD_TINY)

        self._proto_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_SMALL)
        self._proto_frame.pack(fill="x", padx=PAD_INNER)

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Top Source IPs ────────────────────────────────────────────────────
        section_header(p, "TOP SOURCE IPs").pack(fill="x", padx=PAD_INNER,
                                                   pady=PAD_TINY)
        self._src_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_SMALL)
        self._src_frame.pack(fill="x", padx=PAD_INNER)

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Top Destination IPs ───────────────────────────────────────────────
        section_header(p, "TOP DESTINATION IPs").pack(fill="x", padx=PAD_INNER,
                                                        pady=PAD_TINY)
        self._dst_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_SMALL)
        self._dst_frame.pack(fill="x", padx=PAD_INNER)

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Top Ports ─────────────────────────────────────────────────────────
        section_header(p, "TOP DESTINATION PORTS").pack(fill="x", padx=PAD_INNER,
                                                          pady=PAD_TINY)
        self._port_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_SMALL)
        self._port_frame.pack(fill="x", padx=PAD_INNER)

        # Payload stats
        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)
        section_header(p, "PAYLOAD STATISTICS").pack(fill="x", padx=PAD_INNER,
                                                       pady=PAD_TINY)
        payload_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_SMALL)
        payload_frame.pack(fill="x", padx=PAD_INNER)

        self._lbl_total_payload    = self._total_row(payload_frame, "Total Payload")
        self._lbl_with_payload     = self._total_row(payload_frame, "Pkts w/ Payload")
        self._lbl_without_payload  = self._total_row(payload_frame, "Pkts w/o Payload")
        self._lbl_largest_payload  = self._total_row(payload_frame, "Largest Payload")
        self._lbl_avg_payload      = self._total_row(payload_frame, "Avg Payload")

    def refresh(self, packets: list[dict], flows: list[dict]) -> None:
        """
        Recalculate all statistics and update the display.
        Call this whenever new packets arrive.
        """
        if not packets:
            return

        summary = build_session_summary(packets, flows)

        # Totals
        self._lbl_packets.configure( text=f"{summary['total_packets']:,}")
        self._lbl_bytes.configure(   text=format_bytes(summary["total_bytes"]))
        ps = summary["payload_stats"]
        self._lbl_payload.configure( text=format_bytes(ps["total_payload_bytes"]))
        self._lbl_flows.configure(   text=f"{summary['total_flows']:,}")

        # Direction
        dd = summary["direction_distribution"]
        total = max(summary["total_packets"], 1)
        self._lbl_incoming.configure(
            text=f"{dd['INCOMING']:,}  ({100*dd['INCOMING']//total}%)")
        self._lbl_outgoing.configure(
            text=f"{dd['OUTGOING']:,}  ({100*dd['OUTGOING']//total}%)")
        self._lbl_internal.configure(
            text=f"{dd['INTERNAL']:,}  ({100*dd['INTERNAL']//total}%)")
        self._lbl_unknown_d.configure(
            text=f"{dd['UNKNOWN']:,}  ({100*dd['UNKNOWN']//total}%)")

        # Protocol distribution — rebuild bar widgets
        for widget in self._proto_frame.winfo_children():
            widget.destroy()

        max_count = max((r["count"] for r in summary["protocol_distribution"]), default=1)

        for row in summary["protocol_distribution"][:10]:
            self._bar_row(self._proto_frame,
                          row["protocol"],
                          row["count"],
                          max_count,
                          f"{row['percent']}%")

        # Top IPs
        self._fill_ip_list(self._src_frame,
                           summary["top_ips"]["top_sources"])
        self._fill_ip_list(self._dst_frame,
                           summary["top_ips"]["top_destinations"])

        # Top ports
        for widget in self._port_frame.winfo_children():
            widget.destroy()

        for row in summary["top_ports"][:10]:
            service = f"  ({row['service']})" if row["service"] else ""
            self._stat_row(self._port_frame,
                           f"{row['port']}{service}",
                           f"{row['count']:,}")

        # Payload stats
        self._lbl_total_payload.configure(
            text=format_bytes(ps["total_payload_bytes"]))
        self._lbl_with_payload.configure(
            text=f"{ps['packets_with_payload']:,}")
        self._lbl_without_payload.configure(
            text=f"{ps['packets_without_payload']:,}")
        self._lbl_largest_payload.configure(
            text=format_bytes(ps["largest_payload"]))
        self._lbl_avg_payload.configure(
            text=format_bytes(ps["average_payload"]))

    # ── Widget helpers ─────────────────────────────────────────────────────────

    def _total_row(self, parent, label: str) -> tk.Label:
        """A label/value row; returns the value label for later updates."""
        row = tk.Frame(parent, bg=BG_CARD)
        row.pack(fill="x", pady=1)
        tk.Label(row, text=label, bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_SMALL, width=18, anchor="w").pack(side="left")
        val = tk.Label(row, text="—", bg=BG_CARD, fg=FG_PRIMARY,
                       font=FONT_MONO, anchor="w")
        val.pack(side="left")
        return val

    def _bar_row(self, parent, label: str, count: int,
                 max_count: int, pct_text: str) -> None:
        """A text bar chart row."""
        row = tk.Frame(parent, bg=BG_CARD)
        row.pack(fill="x", pady=1)

        tk.Label(row, text=label, bg=BG_CARD, fg=FG_PRIMARY,
                 font=FONT_SMALL, width=12, anchor="w").pack(side="left")

        # Bar — scaled to max_count, max width 120px
        bar_width = max(1, int(120 * count / max_count))
        bar = tk.Frame(row, bg=FG_ACCENT, height=10, width=bar_width)
        bar.pack(side="left", padx=(0, PAD_SMALL))
        bar.pack_propagate(False)

        tk.Label(row, text=f"{count:,}  {pct_text}", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_SMALL, anchor="w").pack(side="left")

    def _stat_row(self, parent, label: str, value: str) -> None:
        """Simple two-column text row."""
        row = tk.Frame(parent, bg=BG_CARD)
        row.pack(fill="x", pady=1)
        tk.Label(row, text=label, bg=BG_CARD, fg=FG_PRIMARY,
                 font=FONT_SMALL, width=22, anchor="w").pack(side="left")
        tk.Label(row, text=value, bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_MONO, anchor="w").pack(side="left")

    def _fill_ip_list(self, frame: tk.Frame, ip_list: list[dict]) -> None:
        """Rebuild an IP ranking list."""
        for widget in frame.winfo_children():
            widget.destroy()

        if not ip_list:
            tk.Label(frame, text="(no data)", bg=BG_CARD,
                     fg=FG_MUTED, font=FONT_SMALL).pack(anchor="w")
            return

        max_count = ip_list[0]["count"]
        for entry in ip_list[:10]:
            self._bar_row(frame, entry["ip"], entry["count"], max_count, "")
