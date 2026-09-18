"""
ui/flow_window.py

Flow Investigation window.

Instead of individual packets, this shows network conversations —
every TCP/UDP exchange grouped by endpoint pair.

An analyst can see at a glance:
  • Which machines are talking?
  • How much data exchanged?
  • How long did the conversation last?
  • Is anything unusual about the flow volume or timing?
"""

import tkinter as tk
from tkinter import ttk, messagebox

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_WARNING, FG_DANGER,
    FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
    FLOW_WINDOW_SIZE,
)
from ui.widgets import (
    DarkButton, StatusBar, horizontal_separator,
    section_header, detail_row, risk_color,
)
from evidence.sessions import format_bytes


class FlowWindow:
    """
    Flow Investigation workstation.

    Parameters
    ----------
    parent      : Tk root window
    session_id  : active session ID
    packets     : list of parsed packet dicts from the capture window
    flows       : list of flow dicts from the FlowTracker
    """

    def __init__(self, parent: tk.Tk, session_id: str,
                 packets: list[dict], flows: list[dict]):
        self.parent     = parent
        self.session_id = session_id
        self._packets   = packets
        self._flows     = flows

        self.window = tk.Toplevel(parent)
        self.window.title("Flow Investigation")
        self.window.geometry(FLOW_WINDOW_SIZE)
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

        self._build_ui()
        self._populate_flow_table()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        horizontal_separator(self.window).pack(fill="x")

        body = tk.Frame(self.window, bg=BG_DARK)
        body.pack(fill="both", expand=True)

        self._build_flow_table(body)
        self._build_detail_panel(body)

        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")
        self._status_bar.set_status(f"Flows: {len(self._flows)}", "idle")

    def _build_header(self) -> None:
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        left = tk.Frame(header, bg=BG_CARD)
        left.pack(side="left")

        tk.Label(left, text="FLOW INVESTIGATION", bg=BG_CARD, fg=FG_ACCENT,
                 font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(left, text="Network conversations grouped by endpoint pair",
                 bg=BG_CARD, fg=FG_SECONDARY, font=FONT_SMALL).pack(anchor="w")

        right = tk.Frame(header, bg=BG_CARD)
        right.pack(side="right")

        DarkButton(right, "REFRESH", command=self._refresh).pack(side="right", padx=2)
        DarkButton(right, "EXPORT CSV",
                   command=self._export_csv).pack(side="right", padx=2)

        # Filter bar
        filter_row = tk.Frame(header, bg=BG_CARD)
        filter_row.pack(fill="x", pady=(PAD_SMALL, 0))

        tk.Label(filter_row, text="FILTER:", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_LABEL).pack(side="left")

        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())

        ttk.Entry(filter_row, textvariable=self._filter_var, width=30
                  ).pack(side="left", padx=PAD_SMALL)

        # Protocol quick-filter buttons
        for proto in ("ALL", "TCP", "UDP", "DNS", "ICMP"):
            tk.Button(
                filter_row, text=proto,
                bg=BG_DARK, fg=FG_SECONDARY,
                font=FONT_SMALL, relief="flat", bd=0, cursor="hand2",
                command=lambda p=proto: self._quick_proto_filter(p)
            ).pack(side="left", padx=1)

    def _build_flow_table(self, parent: tk.Frame) -> None:
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(side="left", fill="both", expand=True)

        cols = ("FLOW", "PROTOCOL", "SOURCE", "DESTINATION",
                "PACKETS", "BYTES", "DURATION", "RISK")
        col_widths = {
            "FLOW": 60, "PROTOCOL": 70,
            "SOURCE": 150, "DESTINATION": 150,
            "PACKETS": 80, "BYTES": 90,
            "DURATION": 90, "RISK": 70,
        }

        self._flow_tree = ttk.Treeview(frame, columns=cols,
                                        show="headings", selectmode="browse")

        for col in cols:
            self._flow_tree.heading(col, text=col,
                                     command=lambda c=col: self._sort_by(c))
            self._flow_tree.column(col, width=col_widths.get(col, 90),
                                    minwidth=40, anchor="w")

        # Alternating row colours
        self._flow_tree.tag_configure("even", background="#161b22")
        self._flow_tree.tag_configure("odd",  background="#1c2128")
        self._flow_tree.tag_configure("risk_medium", foreground=FG_WARNING)
        self._flow_tree.tag_configure("risk_high",   foreground=FG_DANGER)

        scroll_y = ttk.Scrollbar(frame, orient="vertical",
                                  command=self._flow_tree.yview)
        scroll_x = ttk.Scrollbar(frame, orient="horizontal",
                                  command=self._flow_tree.xview)

        self._flow_tree.configure(yscrollcommand=scroll_y.set,
                                   xscrollcommand=scroll_x.set)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self._flow_tree.pack(fill="both", expand=True)

        self._flow_tree.bind("<<TreeviewSelect>>", self._on_flow_selected)

        # Sort state
        self._sort_col       = "PACKETS"
        self._sort_ascending = False

    def _build_detail_panel(self, parent: tk.Frame) -> None:
        panel = tk.Frame(parent, bg=BG_CARD, width=320)
        panel.pack(side="right", fill="y")
        panel.pack_propagate(False)

        info = tk.Frame(panel, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        info.pack(fill="x")

        section_header(info, "FLOW DETAILS", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        self._flow_detail_labels = {}

        fields = [
            ("flow_num",      "Flow #"),
            ("protocol",      "Protocol"),
            ("_endpoints",    "── ENDPOINTS"),
            ("src_ip",        "Source IP"),
            ("src_port",      "Source Port"),
            ("dst_ip",        "Destination IP"),
            ("dst_port",      "Destination Port"),
            ("_stats",        "── STATISTICS"),
            ("packet_count",  "Packets"),
            ("byte_count",    "Bytes"),
            ("first_seen",    "First Seen"),
            ("last_seen",     "Last Seen"),
            ("duration",      "Duration"),
            ("direction",     "Direction"),
            ("risk_level",    "Risk"),
        ]

        for key, label_text in fields:
            if key.startswith("_"):
                tk.Label(info, text=label_text, bg=BG_CARD,
                         fg=FG_MUTED, font=FONT_SMALL, anchor="w"
                         ).pack(fill="x", pady=(4, 0))
            else:
                _, val = detail_row(info, label_text, "—", bg=BG_CARD)
                self._flow_detail_labels[key] = val

        horizontal_separator(panel, bg=BG_CARD).pack(fill="x", pady=PAD_SMALL)

        # Action buttons
        actions = tk.Frame(panel, bg=BG_CARD, padx=PAD_INNER)
        actions.pack(fill="x")

        section_header(actions, "ACTIONS", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        DarkButton(actions, "VIEW PACKETS IN CAPTURE",
                   command=self._view_flow_packets).pack(fill="x", pady=1)
        DarkButton(actions, "ADD NOTE",
                   command=self._add_note).pack(fill="x", pady=1)
        DarkButton(actions, "MARK AS INVESTIGATED",
                   command=self._mark_investigated).pack(fill="x", pady=1)

        # Flow packets mini-table
        horizontal_separator(panel, bg=BG_CARD).pack(fill="x", pady=PAD_SMALL)

        section_label = tk.Label(panel, text="FLOW PACKETS (top 20)",
                                  bg=BG_CARD, fg=FG_SECONDARY,
                                  font=FONT_CARD_TITLE, anchor="w")
        section_label.pack(fill="x", padx=PAD_INNER)

        mini_frame = tk.Frame(panel, bg=BG_CARD)
        mini_frame.pack(fill="both", expand=True, padx=PAD_TINY)

        mini_cols = ("#", "TIME", "SIZE", "PAYLOAD")
        self._mini_tree = ttk.Treeview(mini_frame, columns=mini_cols,
                                        show="headings", height=8)
        for col in mini_cols:
            w = {"#": 50, "TIME": 80, "SIZE": 70, "PAYLOAD": 70}.get(col, 60)
            self._mini_tree.heading(col, text=col)
            self._mini_tree.column(col, width=w, anchor="w")

        mini_scroll = ttk.Scrollbar(mini_frame, orient="vertical",
                                     command=self._mini_tree.yview)
        self._mini_tree.configure(yscrollcommand=mini_scroll.set)
        mini_scroll.pack(side="right", fill="y")
        self._mini_tree.pack(fill="both", expand=True)

        self._selected_flow: dict | None = None

    # ── Data Population ───────────────────────────────────────────────────────

    def _populate_flow_table(self) -> None:
        """Fill the flow table from self._flows."""
        self._flow_tree.delete(*self._flow_tree.get_children())

        flows = self._get_filtered_flows()

        for i, flow in enumerate(flows, start=1):
            # Calculate duration from first/last seen timestamps
            duration_str = _calc_duration(
                flow.get("first_seen", ""),
                flow.get("last_seen", "")
            )

            tag = "even" if i % 2 == 0 else "odd"
            risk = flow.get("risk_level", "NONE")
            if risk == "HIGH":
                tag = "risk_high"
            elif risk == "MEDIUM":
                tag = "risk_medium"

            src = f"{flow.get('src_ip', '?')}:{flow.get('src_port', '?')}"
            dst = f"{flow.get('dst_ip', '?')}:{flow.get('dst_port', '?')}"

            self._flow_tree.insert(
                "", "end", iid=flow["flow_id"],
                values=(
                    i,
                    flow.get("protocol", "?"),
                    src,
                    dst,
                    f"{flow.get('packet_count', 0):,}",
                    format_bytes(flow.get("byte_count", 0)),
                    duration_str,
                    risk,
                ),
                tags=(tag,),
            )

        self._status_bar.set_status(
            f"Showing {len(flows):,} of {len(self._flows):,} flows", "idle"
        )

    def _get_filtered_flows(self) -> list[dict]:
        """Apply current filter text and protocol filter to flow list."""
        text   = self._filter_var.get().lower().strip()
        result = self._flows

        if text:
            result = [
                f for f in result
                if text in (f.get("src_ip") or "").lower()
                or text in (f.get("dst_ip") or "").lower()
                or text in str(f.get("src_port") or "")
                or text in str(f.get("dst_port") or "")
                or text in (f.get("protocol") or "").lower()
            ]

        if hasattr(self, "_proto_filter") and self._proto_filter != "ALL":
            result = [f for f in result
                      if f.get("protocol", "").upper() == self._proto_filter]

        # Sort
        col_map = {
            "FLOW":     None,
            "PROTOCOL": "protocol",
            "SOURCE":   "src_ip",
            "DESTINATION": "dst_ip",
            "PACKETS":  "packet_count",
            "BYTES":    "byte_count",
            "RISK":     "risk_level",
        }
        sort_key = col_map.get(self._sort_col)
        if sort_key:
            result = sorted(
                result,
                key=lambda f: f.get(sort_key) or 0,
                reverse=not self._sort_ascending
            )

        return result

    def _on_flow_selected(self, event) -> None:
        """Show details for the selected flow."""
        sel = self._flow_tree.selection()
        if not sel:
            return

        flow_id = sel[0]
        flow = next((f for f in self._flows if f["flow_id"] == flow_id), None)
        if not flow:
            return

        self._selected_flow = flow
        self._show_flow_details(flow)
        self._populate_mini_packet_table(flow_id)

    def _show_flow_details(self, flow: dict) -> None:
        """Fill the detail panel with flow data."""
        duration_str = _calc_duration(
            flow.get("first_seen", ""),
            flow.get("last_seen", "")
        )

        updates = {
            "flow_num":     flow.get("flow_id", "—")[:20],
            "protocol":     flow.get("protocol", "—"),
            "src_ip":       flow.get("src_ip") or "—",
            "src_port":     str(flow.get("src_port") or "—"),
            "dst_ip":       flow.get("dst_ip") or "—",
            "dst_port":     str(flow.get("dst_port") or "—"),
            "packet_count": f"{flow.get('packet_count', 0):,}",
            "byte_count":   format_bytes(flow.get("byte_count", 0)),
            "first_seen":   (flow.get("first_seen") or "—")[11:19],
            "last_seen":    (flow.get("last_seen")  or "—")[11:19],
            "duration":     duration_str,
            "direction":    flow.get("direction", "—"),
            "risk_level":   flow.get("risk_level", "NONE"),
        }

        for key, value in updates.items():
            if key in self._flow_detail_labels:
                self._flow_detail_labels[key].configure(text=value)

        risk = flow.get("risk_level", "NONE")
        if "risk_level" in self._flow_detail_labels:
            self._flow_detail_labels["risk_level"].configure(
                fg=risk_color(risk)
            )

    def _populate_mini_packet_table(self, flow_id: str) -> None:
        """Show the first 20 packets belonging to this flow."""
        self._mini_tree.delete(*self._mini_tree.get_children())

        flow_packets = [
            p for p in self._packets
            if p.get("flow_id") == flow_id
        ][:20]

        for p in flow_packets:
            self._mini_tree.insert("", "end", values=(
                p.get("packet_number", ""),
                (p.get("capture_time") or "")[11:19],
                f"{p.get('packet_size', 0):,} B",
                f"{p.get('payload_size', 0):,} B",
            ))

    # ── Actions ───────────────────────────────────────────────────────────────

    def _view_flow_packets(self) -> None:
        if not self._selected_flow:
            return
        messagebox.showinfo(
            "Filter Tip",
            f"In the Capture window, set the filter to:\n\n"
            f"    {self._selected_flow.get('src_ip')}\n\n"
            f"to see packets for this flow.",
            parent=self.window
        )

    def _add_note(self) -> None:
        if not self._selected_flow:
            messagebox.showwarning("No Selection", "Select a flow first.",
                                    parent=self.window)
            return
        _NoteDialog(self.window, self.session_id,
                    "flow", self._selected_flow["flow_id"])

    def _mark_investigated(self) -> None:
        if not self._selected_flow:
            return
        self._selected_flow["status"] = "INVESTIGATED"
        messagebox.showinfo("Marked",
                            "Flow marked as investigated.",
                            parent=self.window)

    def _apply_filter(self) -> None:
        self._populate_flow_table()

    def _quick_proto_filter(self, proto: str) -> None:
        self._proto_filter = proto
        self._populate_flow_table()

    def _sort_by(self, column: str) -> None:
        if self._sort_col == column:
            self._sort_ascending = not self._sort_ascending
        else:
            self._sort_col       = column
            self._sort_ascending = False
        self._populate_flow_table()

    def _refresh(self) -> None:
        self._populate_flow_table()

    def _export_csv(self) -> None:
        import csv
        import pathlib
        import datetime

        path = pathlib.Path.home() / "PayloadCaptureExports"
        path.mkdir(parents=True, exist_ok=True)

        filename = path / f"flows_{self.session_id}_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv"

        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "flow_id", "protocol", "src_ip", "src_port",
                    "dst_ip", "dst_port", "packet_count", "byte_count",
                    "first_seen", "last_seen", "direction", "risk_level",
                ])
                writer.writeheader()
                writer.writerows(self._flows)

            messagebox.showinfo("Exported",
                                f"Flows exported to:\n{filename}",
                                parent=self.window)
        except Exception as e:
            messagebox.showerror("Export Error", str(e), parent=self.window)


# ─── Note Dialog ──────────────────────────────────────────────────────────────

class _NoteDialog:
    """Simple pop-up for attaching an analyst note to an object."""

    def __init__(self, parent, session_id: str, target_type: str, target_id: str):
        win = tk.Toplevel(parent)
        win.title("Add Analyst Note")
        win.geometry("400x250")
        win.configure(bg=BG_DARK)
        win.grab_set()

        tk.Label(win, text=f"Add note to {target_type} {target_id[:30]}",
                 bg=BG_DARK, fg=FG_SECONDARY, font=FONT_SMALL,
                 wraplength=380).pack(fill="x", padx=PAD_OUTER, pady=PAD_INNER)

        text = tk.Text(win, bg=BG_INPUT, fg=FG_PRIMARY,
                       font=FONT_MONO, height=6, wrap="word", relief="flat")
        text.pack(fill="both", expand=True, padx=PAD_OUTER)

        def save():
            content = text.get("1.0", "end").strip()
            if content:
                from evidence.database import insert_note
                insert_note(session_id, target_type, target_id, content)
            win.destroy()

        btn_row = tk.Frame(win, bg=BG_DARK)
        btn_row.pack(fill="x", padx=PAD_OUTER, pady=PAD_INNER)

        from ui.widgets import DarkButton as DB
        DB(btn_row, "SAVE NOTE", command=save, accent=True).pack(side="left")
        DB(btn_row, "CANCEL", command=win.destroy).pack(side="left", padx=PAD_SMALL)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _calc_duration(first_seen: str, last_seen: str) -> str:
    """Return HH:MM:SS duration between two ISO timestamp strings."""
    if not first_seen or not last_seen:
        return "—"
    try:
        t1 = _parse_time(first_seen)
        t2 = _parse_time(last_seen)
        delta = int((t2 - t1).total_seconds())
        if delta < 0:
            delta = 0
        h = delta // 3600
        m = (delta % 3600) // 60
        s = delta % 60
        return f"{h:02d}:{m:02d}:{s:02d}"
    except Exception:
        return "—"


def _parse_time(ts: str):
    """Parse an ISO timestamp, tolerating various formats."""
    import datetime
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%H:%M:%S"):
        try:
            return datetime.datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return datetime.datetime.now()
