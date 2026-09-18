"""
ui/capture_window.py

The primary capture workstation window.

This window:
1. Lets the analyst choose a network interface and filter
2. Starts/stops/pauses Scapy packet capture in a background thread
3. Displays live packets in a table (read from the queue via root.after)
4. Shows detailed packet information in a side panel
5. Shows payload in ASCII / HEX / Binary / Raw tabs

Threading model:
    CaptureEngine (background thread)
         │  puts raw Scapy packets into queue
         ▼
    _poll_queue() called via root.after(100, ...)
         │  reads from queue, calls parser
         ▼
    _add_packet_to_table()  — safe because we're on the main thread now
"""

import tkinter as tk
from tkinter import ttk, messagebox
import queue
import socket
import datetime

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_WARNING, FG_DANGER,
    FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL, PAD_TINY,
    CAPTURE_WINDOW_SIZE, RISK_COLORS,
)
from ui.widgets import (
    DarkButton, StatusBar, MonoText, build_packet_table,
    horizontal_separator, detail_row, section_header, risk_color,
)
from capture.engine import CaptureEngine, get_available_interfaces, SCAPY_AVAILABLE
from capture.filters import translate_filter, FILTER_SUGGESTIONS
from packets.parser import parse_packet, get_payload_bytes
from packets.payload import analyse_payload
from flows.tracker import FlowTracker
import config.settings as settings


# Maximum number of rows kept in the live packet table.
# Older rows are pruned when this limit is reached.
MAX_TABLE_ROWS = 3000


class CaptureWindow:
    """
    Live packet capture workstation.

    Parameters
    ----------
    parent          : the Tk root window
    session_id      : active investigation session ID
    on_stats_update : callback(packets, flows, payload_bytes, findings)
                      called whenever statistics change
    """

    def __init__(self, parent: tk.Tk, session_id: str, on_stats_update=None):
        self.parent          = parent
        self.session_id      = session_id
        self.on_stats_update = on_stats_update

        # Shared packet queue between capture thread and UI thread
        self._packet_queue: queue.Queue = queue.Queue()

        # Capture engine (manages the Scapy background thread)
        self._engine = CaptureEngine(self._packet_queue)

        # Flow tracker (aggregates packets into conversations)
        self._flow_tracker = FlowTracker()

        # In-memory list of parsed packet dicts (parallel to table rows)
        self._packets: list[dict] = []
        self._packet_payloads: dict[int, bytes] = {}  # packet_number → raw bytes
        self._raw_packets: list = []   # original Scapy objects (for PCAP export)
        self._capture_mode: str = "LIVE"   # LIVE or PCAP

        # Session stats
        self._total_payload_bytes = 0
        self._row_count           = 0

        # Get local IP for direction detection
        self._local_ip = self._get_local_ip()

        # Build the window
        self.window = tk.Toplevel(parent)
        self.window.title("Payload Capture — Live Network Monitor")
        self.window.geometry(CAPTURE_WINDOW_SIZE)
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_ui()
        self._populate_interfaces()

        # Start polling the packet queue
        self.window.after(100, self._poll_queue)

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Top toolbar ──────────────────────────────────────────────────────
        self._build_toolbar()
        horizontal_separator(self.window).pack(fill="x")

        # ── Filter bar ───────────────────────────────────────────────────────
        self._build_filter_bar()
        horizontal_separator(self.window).pack(fill="x")

        # ── Main body — left packet table, right details panel ───────────────
        body = tk.Frame(self.window, bg=BG_DARK)
        body.pack(fill="both", expand=True)

        self._build_packet_table(body)
        self._build_details_panel(body)

        # ── Status bar ───────────────────────────────────────────────────────
        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

        # Scapy availability warning
        if not SCAPY_AVAILABLE:
            self._status_bar.set_status(
                "⚠  Scapy not found — install scapy and Npcap to capture packets",
                "error"
            )

        # Stats refresh every 5 seconds while capturing
        self.window.after(5000, self._auto_refresh_stats)

    def _build_toolbar(self) -> None:
        toolbar = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL)
        toolbar.pack(fill="x")

        # Interface selector
        tk.Label(toolbar, text="INTERFACE:", bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_LABEL).pack(side="left", padx=(PAD_OUTER, PAD_SMALL))

        self._iface_var = tk.StringVar()
        self._iface_combo = ttk.Combobox(
            toolbar, textvariable=self._iface_var, width=30, state="readonly"
        )
        self._iface_combo.pack(side="left", padx=(0, PAD_OUTER))

        # Capture status indicator
        self._capture_status_label = tk.Label(
            toolbar, text="● IDLE", bg=BG_CARD, fg=FG_SECONDARY, font=FONT_BODY
        )
        self._capture_status_label.pack(side="right", padx=PAD_OUTER)

        # Action buttons (right-to-left order for visual balance)
        btn_defs = [
            ("SAVE SESSION", self._save_session,   False),
            ("STATISTICS",   self._open_stats,     False),
            ("IMPORT PCAP",  self._open_pcap,      False),
            ("CLEAR",        self._clear_capture,  False),
            ("PAUSE",        self._pause_capture,  False),
            ("STOP",         self._stop_capture,   False),
            ("START CAPTURE",self._start_capture,  True),
        ]

        self._btn_start = None
        self._btn_stop  = None
        self._btn_pause = None

        for label, cmd, accent in btn_defs:
            btn = DarkButton(toolbar, text=label, command=cmd, accent=accent)
            btn.pack(side="left", padx=2)
            if label == "START CAPTURE":
                self._btn_start = btn
            elif label == "STOP":
                self._btn_stop = btn
            elif label == "PAUSE":
                self._btn_pause = btn

    def _build_filter_bar(self) -> None:
        filter_frame = tk.Frame(self.window, bg=BG_DARK, pady=PAD_TINY)
        filter_frame.pack(fill="x", padx=PAD_OUTER)

        tk.Label(filter_frame, text="FILTER:", bg=BG_DARK, fg=FG_SECONDARY,
                 font=FONT_LABEL).pack(side="left", padx=(0, PAD_SMALL))

        self._filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=self._filter_var,
                                 width=40)
        filter_entry.pack(side="left", padx=(0, PAD_SMALL))
        filter_entry.bind("<Return>", lambda e: self._apply_filter())

        DarkButton(filter_frame, "APPLY", command=self._apply_filter
                   ).pack(side="left")

        # Suggestion buttons
        tk.Label(filter_frame, text="Quick:", bg=BG_DARK, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(side="left", padx=(PAD_OUTER, PAD_SMALL))

        for suggestion in ["TCP", "UDP", "DNS", "HTTPS", "HTTP"]:
            tk.Button(
                filter_frame, text=suggestion,
                bg=BG_DARK, fg=FG_SECONDARY,
                font=FONT_SMALL, relief="flat", bd=0, cursor="hand2",
                command=lambda s=suggestion: self._quick_filter(s)
            ).pack(side="left", padx=1)

    def _build_packet_table(self, parent: tk.Frame) -> None:
        """Build the scrollable packet list on the left side."""
        table_frame = tk.Frame(parent, bg=BG_DARK)
        table_frame.pack(side="left", fill="both", expand=True)

        # Table itself
        self._packet_tree = build_packet_table(table_frame)

        scroll_y = ttk.Scrollbar(table_frame, orient="vertical",
                                 command=self._packet_tree.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal",
                                 command=self._packet_tree.xview)

        self._packet_tree.configure(
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
        )

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self._packet_tree.pack(fill="both", expand=True)

        # Selection callback
        self._packet_tree.bind("<<TreeviewSelect>>", self._on_packet_selected)

        # Right-click context menu
        self._context_menu = tk.Menu(self.window, tearoff=0, bg=BG_CARD,
                                     fg=FG_PRIMARY, activebackground=BG_INPUT,
                                     relief="flat", bd=0)
        self._context_menu.add_command(label="Copy Source IP",
                                       command=self._copy_src_ip)
        self._context_menu.add_command(label="Copy Destination IP",
                                       command=self._copy_dst_ip)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="Filter by Source IP",
                                       command=self._filter_by_src_ip)
        self._context_menu.add_command(label="Filter by Destination IP",
                                       command=self._filter_by_dst_ip)

        self._packet_tree.bind("<Button-3>", self._on_right_click)

    def _build_details_panel(self, parent: tk.Frame) -> None:
        """Build the right-side details panel with packet info + payload tabs."""
        panel = tk.Frame(parent, bg=BG_CARD, width=340)
        panel.pack(side="right", fill="y")
        panel.pack_propagate(False)

        # ── Packet information ────────────────────────────────────────────────
        info_section = tk.Frame(panel, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        info_section.pack(fill="x")

        section_header(info_section, "PACKET INFORMATION", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        # We store the value label refs so we can update them on selection
        self._detail_labels = {}

        detail_fields = [
            ("pkt_num",     "Packet #"),
            ("capture_time","Time"),
            ("direction",   "Direction"),
            ("protocol",    "Protocol"),
            # Spacer label
            ("_net",        "── NETWORK"),
            ("src_ip",      "Source IP"),
            ("src_port",    "Source Port"),
            ("dst_ip",      "Destination IP"),
            ("dst_port",    "Destination Port"),
            # Sizes
            ("_size",       "── SIZE"),
            ("packet_size", "Packet Size"),
            ("payload_size","Payload Size"),
            # Analysis
            ("_analysis",   "── ANALYSIS"),
            ("risk_level",  "Risk Level"),
        ]

        for key, label_text in detail_fields:
            if key.startswith("_"):
                # Section divider
                tk.Label(info_section, text=label_text, bg=BG_CARD,
                         fg=FG_MUTED, font=FONT_SMALL, anchor="w"
                         ).pack(fill="x", pady=(4, 0))
            else:
                _, val_lbl = detail_row(info_section, label_text, "—", bg=BG_CARD)
                self._detail_labels[key] = val_lbl

        horizontal_separator(panel, bg=BG_CARD).pack(fill="x", pady=PAD_SMALL)

        # ── Payload tabs ─────────────────────────────────────────────────────
        payload_label = tk.Label(panel, text="PAYLOAD", bg=BG_CARD,
                                 fg=FG_SECONDARY, font=FONT_CARD_TITLE,
                                 anchor="w")
        payload_label.pack(fill="x", padx=PAD_INNER)

        # Payload stats row (entropy, printable %, sha256)
        stats_row = tk.Frame(panel, bg=BG_CARD)
        stats_row.pack(fill="x", padx=PAD_INNER)

        self._entropy_label    = tk.Label(stats_row, text="Entropy: —",
                                          bg=BG_CARD, fg=FG_SECONDARY,
                                          font=FONT_SMALL)
        self._entropy_label.pack(side="left")

        self._printable_label  = tk.Label(stats_row, text="  Printable: —",
                                          bg=BG_CARD, fg=FG_SECONDARY,
                                          font=FONT_SMALL)
        self._printable_label.pack(side="left")

        # SHA-256 (takes full width)
        self._sha256_label = tk.Label(panel, text="SHA-256: —",
                                      bg=BG_CARD, fg=FG_SECONDARY,
                                      font=FONT_SMALL, anchor="w",
                                      wraplength=310)
        self._sha256_label.pack(fill="x", padx=PAD_INNER)

        horizontal_separator(panel, bg=BG_CARD).pack(fill="x", pady=(4, 0))

        # Tab notebook for ASCII / HEX / BINARY
        nb = ttk.Notebook(panel)
        nb.pack(fill="both", expand=True, padx=PAD_TINY, pady=PAD_TINY)

        self._ascii_view  = MonoText(nb)
        self._hex_view    = MonoText(nb)
        self._binary_view = MonoText(nb)

        nb.add(self._ascii_view,  text="ASCII")
        nb.add(self._hex_view,    text="HEX")
        nb.add(self._binary_view, text="BINARY")

    # ── Interface population ──────────────────────────────────────────────────

    def _populate_interfaces(self) -> None:
        """Fill the interface drop-down with available network interfaces."""
        interfaces = get_available_interfaces()

        if not interfaces:
            self._iface_combo["values"] = ["(no interfaces found)"]
            self._iface_combo.current(0)
            return

        self._iface_combo["values"] = interfaces

        # Try to select the default interface from settings
        default = settings.get("default_interface")
        if default and default in interfaces:
            self._iface_var.set(default)
        else:
            self._iface_combo.current(0)

    # ── Capture Controls ──────────────────────────────────────────────────────

    def _start_capture(self) -> None:
        """Start packet capture on the selected interface."""
        if not SCAPY_AVAILABLE:
            messagebox.showerror(
                "Scapy Required",
                "Scapy is not installed.\n\n"
                "Install it with:\n    pip install scapy\n\n"
                "Npcap is also required on Windows:\n"
                "    https://npcap.com",
                parent=self.window
            )
            return

        if self._engine.is_capturing():
            return

        iface  = self._iface_var.get()
        filter_text = self._filter_var.get().strip()
        bpf    = translate_filter(filter_text)

        # Validate interface
        if not iface or "(no interfaces" in iface:
            messagebox.showerror("No Interface",
                                 "Please select a network interface.",
                                 parent=self.window)
            return

        try:
            self._engine.start(interface=iface, bpf_filter=bpf)
        except Exception as e:
            messagebox.showerror("Capture Error", str(e), parent=self.window)
            return

        self._update_capture_status()
        self._status_bar.set_status(f"Capturing on {iface}", "active")

    def _stop_capture(self) -> None:
        """Stop the running capture."""
        self._engine.stop()
        self._update_capture_status()
        self._status_bar.set_status("Capture stopped", "idle")

    def _pause_capture(self) -> None:
        """Toggle capture pause state."""
        if self._engine.is_paused():
            self._engine.resume()
            self._status_bar.set_status("Capture resumed", "active")
        else:
            self._engine.pause()
            self._status_bar.set_status("Capture paused", "paused")
        self._update_capture_status()

    def _clear_capture(self) -> None:
        """Remove all packets from the live table and reset counters."""
        answer = messagebox.askyesno(
            "Clear Capture",
            "Clear all captured packets from the display?\n"
            "(Data already saved to the session is kept.)",
            parent=self.window
        )
        if not answer:
            return

        self._packet_tree.delete(*self._packet_tree.get_children())
        self._packets.clear()
        self._raw_packets.clear()
        self._packet_payloads.clear()
        self._flow_tracker.clear()
        self._row_count = 0
        self._total_payload_bytes = 0
        self._clear_detail_panel()
        self._status_bar.set_status("Display cleared", "idle")
        self._update_right_status()

    def _save_session(self) -> None:
        """Bulk-save all in-memory packets to the database."""
        from evidence import database as db
        if not self._packets:
            messagebox.showinfo("Nothing to Save",
                                "No packets captured yet.", parent=self.window)
            return

        db.insert_packets_bulk(self.session_id, self._packets)

        # Save flows
        for flow in self._flow_tracker.get_all_flows():
            db.upsert_flow(self.session_id, flow)

        # Update session stats
        db.update_session_stats(
            self.session_id,
            packets=len(self._packets),
            bytes_=sum(p.get("packet_size", 0) for p in self._packets),
            flows=self._flow_tracker.flow_count(),
            alerts=0
        )

        messagebox.showinfo("Saved",
                            f"{len(self._packets):,} packets saved to session.",
                            parent=self.window)

    def _apply_filter(self) -> None:
        """Apply the filter (restarts capture if running)."""
        if self._engine.is_capturing():
            self._stop_capture()
            self._start_capture()
        self._status_bar.set_status(
            f"Filter applied: {self._filter_var.get() or '(all traffic)'}", "idle"
        )

    def _quick_filter(self, text: str) -> None:
        """Set filter entry and apply immediately."""
        self._filter_var.set(text)
        self._apply_filter()

    # ── Queue polling ──────────────────────────────────────────────────────────

    def _poll_queue(self) -> None:
        """
        Read packets from the capture queue and update the UI.

        Called every 100 ms via root.after() — runs on the main thread,
        so it is safe to update Tkinter widgets here.

        We process up to 50 packets per poll to avoid blocking the UI
        during heavy traffic bursts.
        """
        BATCH_SIZE = 50

        for _ in range(BATCH_SIZE):
            try:
                message_type, data = self._packet_queue.get_nowait()

                if message_type == "packet":
                    self._handle_raw_packet(data)

                elif message_type == "error":
                    self._status_bar.set_status(f"Capture error: {data}", "error")
                    break

            except queue.Empty:
                break   # no more packets right now

        # Schedule the next poll
        if self.window.winfo_exists():
            self.window.after(100, self._poll_queue)

    def _handle_raw_packet(self, raw_packet) -> None:
        """
        Parse a raw Scapy packet and add it to the display.
        Runs on the main thread (called from _poll_queue).
        """
        # Sequential packet number within this display session
        packet_number = self._row_count + 1

        # Parse to a clean dict
        parsed = parse_packet(raw_packet, packet_number, self._local_ip)

        # Extract raw payload bytes for the detail panel
        payload_bytes = get_payload_bytes(raw_packet)

        # Update flow tracker
        self._flow_tracker.update(parsed)

        # Keep in memory
        self._packets.append(parsed)
        self._raw_packets.append(raw_packet)   # for PCAP export
        if payload_bytes:
            self._packet_payloads[packet_number] = payload_bytes
            self._total_payload_bytes += len(payload_bytes)

        # Add to visible table
        self._add_packet_to_table(parsed)

        # Notify the dashboard of updated stats
        self._notify_stats()

    def _add_packet_to_table(self, parsed: dict) -> None:
        """Insert one row into the packet Treeview."""
        self._row_count += 1
        n = self._row_count

        # Prune the oldest rows if the table is getting too large
        if n > MAX_TABLE_ROWS:
            first_child = self._packet_tree.get_children()[0]
            self._packet_tree.delete(first_child)

        # Format time as HH:MM:SS.mmm
        raw_time = parsed.get("capture_time", "")
        display_time = raw_time[11:23] if len(raw_time) > 11 else raw_time

        src = parsed.get("src_ip") or "—"
        dst = parsed.get("dst_ip") or "—"
        src_port = parsed.get("src_port")
        dst_port = parsed.get("dst_port")
        ports = f"{src_port or ''}  →  {dst_port or ''}" if (src_port or dst_port) else "—"

        risk = parsed.get("risk_level", "NONE")

        row_tag = "even" if n % 2 == 0 else "odd"

        # Add risk-level colouring on top of alternating rows
        if risk == "HIGH":
            row_tag = "risk_high"
        elif risk == "MEDIUM":
            row_tag = "risk_medium"
        elif risk == "CRITICAL":
            row_tag = "risk_critical"

        self._packet_tree.insert(
            "", "end",
            iid=str(n),
            values=(
                n,
                display_time,
                parsed.get("direction", "—"),
                parsed.get("protocol", "—"),
                src,
                dst,
                ports,
                f"{parsed.get('packet_size', 0):,} B",
                f"{parsed.get('payload_size', 0):,} B",
                risk,
            ),
            tags=(row_tag,),
        )

        # Auto-scroll to keep the latest packet visible
        # Only auto-scroll when the user is near the bottom
        self._packet_tree.yview_moveto(1.0)

    # ── Packet Selection ──────────────────────────────────────────────────────

    def _on_packet_selected(self, event) -> None:
        """Called when the user clicks a row in the packet table."""
        selection = self._packet_tree.selection()
        if not selection:
            return

        # The iid is the packet number as a string
        iid = selection[0]
        try:
            packet_number = int(iid)
        except ValueError:
            return

        # Find the matching parsed dict (packet_number is 1-based)
        index = packet_number - 1
        if index < 0 or index >= len(self._packets):
            return

        parsed = self._packets[index]
        self._show_packet_details(parsed)

        # Load payload if available
        payload_bytes = self._packet_payloads.get(packet_number, b"")
        self._show_payload(payload_bytes)

    def _show_packet_details(self, parsed: dict) -> None:
        """Fill the details panel with data from the selected packet."""
        updates = {
            "pkt_num":      str(parsed.get("packet_number", "—")),
            "capture_time": parsed.get("capture_time", "—")[11:23],  # just time
            "direction":    parsed.get("direction", "—"),
            "protocol":     " / ".join(parsed.get("protocol_stack", [])) or
                            parsed.get("protocol", "—"),
            "src_ip":       parsed.get("src_ip") or "—",
            "src_port":     str(parsed.get("src_port") or "—"),
            "dst_ip":       parsed.get("dst_ip") or "—",
            "dst_port":     str(parsed.get("dst_port") or "—"),
            "packet_size":  f"{parsed.get('packet_size', 0):,} bytes",
            "payload_size": f"{parsed.get('payload_size', 0):,} bytes",
            "risk_level":   parsed.get("risk_level", "NONE"),
        }

        for key, value in updates.items():
            if key in self._detail_labels:
                label = self._detail_labels[key]
                label.configure(text=value)

        # Colour the risk level label
        risk = parsed.get("risk_level", "NONE")
        if "risk_level" in self._detail_labels:
            self._detail_labels["risk_level"].configure(
                fg=risk_color(risk)
            )

    def _show_payload(self, payload_bytes: bytes) -> None:
        """Display payload bytes in the ASCII / HEX / BINARY tabs."""
        if not payload_bytes:
            analysis = {
                "sha256": "(no payload)",
                "entropy": 0.0,
                "printable_ratio": 0.0,
                "ascii_preview": "(no payload)",
                "hex_dump": "(no payload)",
                "binary_preview": "(no payload)",
            }
        else:
            preview_size = settings.get("payload_preview_bytes", 512)
            analysis = analyse_payload(payload_bytes)

        self._ascii_view.set_text(analysis["ascii_preview"])
        self._hex_view.set_text(analysis["hex_dump"])
        self._binary_view.set_text(analysis["binary_preview"])

        self._entropy_label.configure(
            text=f"Entropy: {analysis['entropy']:.2f}"
        )
        self._printable_label.configure(
            text=f"  Printable: {analysis['printable_ratio']:.0f}%"
        )
        self._sha256_label.configure(
            text=f"SHA-256: {analysis['sha256']}"
        )

    def _clear_detail_panel(self) -> None:
        """Reset the details panel to blank state."""
        for label in self._detail_labels.values():
            label.configure(text="—", fg=FG_SECONDARY)
        self._entropy_label.configure(text="Entropy: —")
        self._printable_label.configure(text="  Printable: —")
        self._sha256_label.configure(text="SHA-256: —")
        self._ascii_view.set_text("(no packet selected)")
        self._hex_view.set_text("(no packet selected)")
        self._binary_view.set_text("(no packet selected)")

    # ── Context Menu ──────────────────────────────────────────────────────────

    def _on_right_click(self, event) -> None:
        """Show the right-click context menu."""
        row = self._packet_tree.identify_row(event.y)
        if row:
            self._packet_tree.selection_set(row)
            self._context_menu.post(event.x_root, event.y_root)

    def _get_selected_parsed(self) -> dict | None:
        """Return the parsed dict for the currently selected row."""
        sel = self._packet_tree.selection()
        if not sel:
            return None
        try:
            index = int(sel[0]) - 1
            return self._packets[index]
        except (ValueError, IndexError):
            return None

    def _copy_src_ip(self) -> None:
        p = self._get_selected_parsed()
        if p and p.get("src_ip"):
            self.window.clipboard_clear()
            self.window.clipboard_append(p["src_ip"])

    def _copy_dst_ip(self) -> None:
        p = self._get_selected_parsed()
        if p and p.get("dst_ip"):
            self.window.clipboard_clear()
            self.window.clipboard_append(p["dst_ip"])

    def _filter_by_src_ip(self) -> None:
        p = self._get_selected_parsed()
        if p and p.get("src_ip"):
            self._filter_var.set(p["src_ip"])

    def _filter_by_dst_ip(self) -> None:
        p = self._get_selected_parsed()
        if p and p.get("dst_ip"):
            self._filter_var.set(p["dst_ip"])

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _update_capture_status(self) -> None:
        """Update the capture indicator label in the toolbar."""
        if self._engine.is_paused():
            self._capture_status_label.configure(text="● PAUSED", fg=FG_WARNING)
        elif self._engine.is_capturing():
            self._capture_status_label.configure(text="● CAPTURING", fg=FG_SUCCESS)
        else:
            self._capture_status_label.configure(text="● IDLE", fg=FG_SECONDARY)

    def _update_right_status(self) -> None:
        """Update the right side of the status bar with packet/flow counts."""
        self._status_bar.set_right(
            f"Packets: {self._row_count:,}   "
            f"Flows: {self._flow_tracker.flow_count():,}   "
            f"Payload: {self._total_payload_bytes:,} B"
        )

    def _notify_stats(self) -> None:
        """Send updated stats to the main dashboard every ~50 packets."""
        if self.on_stats_update and self._row_count % 50 == 0:
            self.on_stats_update(
                self._row_count,
                self._flow_tracker.flow_count(),
                self._total_payload_bytes,
                0   # findings — Phase 3
            )
        self._update_right_status()

    def _get_local_ip(self) -> str:
        """
        Get the machine's primary IP address.
        Used to determine packet direction (incoming / outgoing).
        Falls back to empty string on failure.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return ""

    def _open_stats(self) -> None:
        """Open the statistics panel in a separate window."""
        from ui.stats_window import StatsWindow
        StatsWindow(self.window, self.session_id,
                    self._packets, self._flow_tracker.get_all_flows())

    def _open_pcap(self) -> None:
        """Open the PCAP import/export window."""
        from ui.pcap_window import PcapWindow
        PcapWindow(
            self.window,
            session_id=self.session_id,
            packet_queue=self._packet_queue,
            raw_packets=self._raw_packets,
            on_import_start=self._set_pcap_mode,
        )

    def _set_pcap_mode(self, filename: str) -> None:
        """Switch the window to PCAP ANALYSIS mode."""
        self._capture_mode = "PCAP"
        self.window.title(
            f"Payload Capture — PCAP ANALYSIS: {filename}"
        )
        self._capture_status_label.configure(
            text="● PCAP ANALYSIS", fg=FG_ACCENT
        )
        self._status_bar.set_status(
            f"Importing PCAP: {filename}", "active"
        )

    def _auto_refresh_stats(self) -> None:
        """Periodically push stats to the parent dashboard."""
        if self.window.winfo_exists():
            self._notify_stats()
            self.window.after(5000, self._auto_refresh_stats)

    def _on_close(self) -> None:
        """Handle the window close button."""
        if self._engine.is_capturing():
            answer = messagebox.askyesno(
                "Capture Running",
                "A capture is in progress.\nStop it and close this window?",
                parent=self.window
            )
            if not answer:
                return
            self._engine.stop()
        self.window.destroy()
