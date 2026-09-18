"""
ui/ip_window.py

IP Investigation window.

Lets the analyst drill into any IP address observed during the session:
  - Classification (public / private / loopback / multicast)
  - Reverse DNS  (presented as a clue, not authoritative proof)
  - Packet and flow statistics for this IP
  - All related flows in a mini table
  - Buttons to cross-launch other modules filtered to this IP

IMPORTANT: This window never labels an IP as "malicious" or "safe".
It presents observations and lets the analyst interpret them.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT, BG_SELECTED,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS,
    FG_WARNING, FG_DANGER, FG_INFO, FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL, PAD_TINY,
    IP_WINDOW_SIZE,
)
from ui.widgets import (
    DarkButton, StatusBar, horizontal_separator,
    section_header, detail_row,
)
from investigation.ip import (
    classify_ip, reverse_dns_lookup,
    build_ip_summary, get_all_ip_addresses,
)
from evidence.sessions import format_bytes


class IPWindow:
    """
    IP Investigation workstation.

    Parameters
    ----------
    parent     : Tk root window
    session_id : active session ID
    packets    : list of parsed packet dicts
    flows      : list of flow dicts
    initial_ip : if given, auto-select this IP on open
    """

    def __init__(self, parent: tk.Tk, session_id: str,
                 packets: list[dict], flows: list[dict],
                 initial_ip: str = ""):
        self.parent     = parent
        self.session_id = session_id
        self._packets   = packets
        self._flows     = flows

        # All unique IPs seen in the session
        self._all_ips   = get_all_ip_addresses(packets)

        # Cache: ip_str → (classification_dict, rdns_str, summary_dict)
        self._cache: dict[str, dict] = {}

        self.window = tk.Toplevel(parent)
        self.window.title("IP Investigation")
        self.window.geometry(IP_WINDOW_SIZE)
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

        self._build_ui()
        self._populate_ip_list()

        if initial_ip:
            self._select_ip(initial_ip)

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        horizontal_separator(self.window).pack(fill="x")

        body = tk.Frame(self.window, bg=BG_DARK)
        body.pack(fill="both", expand=True)

        self._build_ip_list(body)
        self._build_detail_panel(body)

        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

    def _build_header(self) -> None:
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        left = tk.Frame(header, bg=BG_CARD)
        left.pack(side="left")

        tk.Label(left, text="IP INVESTIGATION", bg=BG_CARD,
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(
            left,
            text="IP classification · Reverse DNS · Session traffic summary",
            bg=BG_CARD, fg=FG_SECONDARY, font=FONT_SMALL
        ).pack(anchor="w")

        # Manual IP entry
        right = tk.Frame(header, bg=BG_CARD)
        right.pack(side="right")

        tk.Label(right, text="LOOK UP:", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_LABEL).pack(side="left")

        self._lookup_var = tk.StringVar()
        entry = ttk.Entry(right, textvariable=self._lookup_var, width=18)
        entry.pack(side="left", padx=PAD_SMALL)
        entry.bind("<Return>", lambda e: self._lookup_manual())

        DarkButton(right, "CHECK", command=self._lookup_manual,
                   accent=True).pack(side="left")

        # IP filter
        filter_row = tk.Frame(header, bg=BG_CARD)
        filter_row.pack(fill="x", pady=(PAD_SMALL, 0))

        tk.Label(filter_row, text="FILTER LIST:", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_LABEL).pack(side="left")

        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_list_filter())
        ttk.Entry(filter_row, textvariable=self._filter_var,
                  width=22).pack(side="left", padx=PAD_SMALL)

        # Quick type filters
        for type_label in ("ALL", "PUBLIC", "PRIVATE", "LOOPBACK"):
            tk.Button(
                filter_row, text=type_label,
                bg=BG_CARD, fg=FG_SECONDARY,
                font=FONT_SMALL, relief="flat", bd=0, cursor="hand2", padx=6,
                command=lambda t=type_label: self._quick_type_filter(t)
            ).pack(side="left", padx=1)

        self._type_filter = "ALL"

    def _build_ip_list(self, parent: tk.Frame) -> None:
        """Left pane — all IPs seen in the session."""
        frame = tk.Frame(parent, bg=BG_DARK, width=240)
        frame.pack(side="left", fill="y")
        frame.pack_propagate(False)

        section_header(frame, f"IPs IN SESSION ({len(self._all_ips)})").pack(
            fill="x", padx=PAD_INNER, pady=(PAD_INNER, PAD_TINY)
        )

        list_frame = tk.Frame(frame, bg=BG_DARK)
        list_frame.pack(fill="both", expand=True)

        cols = ("IP", "TYPE", "PKTS")
        self._ip_list = ttk.Treeview(
            list_frame, columns=cols, show="headings", selectmode="browse"
        )
        self._ip_list.heading("IP",   text="IP ADDRESS")
        self._ip_list.heading("TYPE", text="TYPE")
        self._ip_list.heading("PKTS", text="PKTS")
        self._ip_list.column("IP",   width=130, anchor="w")
        self._ip_list.column("TYPE", width=70,  anchor="w")
        self._ip_list.column("PKTS", width=50,  anchor="e")

        self._ip_list.tag_configure("PUBLIC",   foreground=FG_PRIMARY)
        self._ip_list.tag_configure("PRIVATE",  foreground=FG_SUCCESS)
        self._ip_list.tag_configure("LOOPBACK", foreground=FG_MUTED)
        self._ip_list.tag_configure("even",     background="#161b22")
        self._ip_list.tag_configure("odd",      background="#1c2128")

        scroll = ttk.Scrollbar(list_frame, orient="vertical",
                               command=self._ip_list.yview)
        self._ip_list.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self._ip_list.pack(fill="both", expand=True)

        self._ip_list.bind("<<TreeviewSelect>>", self._on_ip_list_select)

    def _build_detail_panel(self, parent: tk.Frame) -> None:
        """Right pane — full detail for the selected IP."""
        panel = tk.Frame(parent, bg=BG_CARD)
        panel.pack(side="right", fill="both", expand=True)

        # Scrollable
        canvas = tk.Canvas(panel, bg=BG_CARD, highlightthickness=0)
        scroll = ttk.Scrollbar(panel, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG_CARD)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(win_id, width=e.width))
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        p = inner

        # ── IP address header ─────────────────────────────────────────────────
        ip_header = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        ip_header.pack(fill="x")

        self._ip_display = tk.Label(
            ip_header, text="Select an IP from the list",
            bg=BG_CARD, fg=FG_ACCENT,
            font=(FONT_CARD_TITLE[0], 18, "bold"), anchor="w"
        )
        self._ip_display.pack(anchor="w")

        self._ip_type_badge = tk.Label(
            ip_header, text="",
            bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_LABEL, anchor="w"
        )
        self._ip_type_badge.pack(anchor="w")

        self._ip_desc_label = tk.Label(
            ip_header, text="",
            bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_SMALL, anchor="w", wraplength=480, justify="left"
        )
        self._ip_desc_label.pack(anchor="w")

        horizontal_separator(p, bg=BG_CARD).pack(fill="x", padx=PAD_INNER,
                                                   pady=PAD_SMALL)

        # Two-column layout for info fields
        cols_frame = tk.Frame(p, bg=BG_CARD)
        cols_frame.pack(fill="x", padx=PAD_INNER)

        left_col  = tk.Frame(cols_frame, bg=BG_CARD)
        right_col = tk.Frame(cols_frame, bg=BG_CARD)
        left_col.pack(side="left", fill="both", expand=True)
        right_col.pack(side="left", fill="both", expand=True)

        # Left column fields
        section_header(left_col, "NETWORK", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_TINY)
        )
        self._lbl = {}   # key → tk.Label for value

        left_fields = [
            ("version",    "IP Version"),
            ("ip_type",    "Type"),
            ("net_class",  "Network Class"),
            ("is_private", "Private Range"),
            ("is_global",  "Global (Public)"),
        ]
        for key, label in left_fields:
            _, v = detail_row(left_col, label, "—", bg=BG_CARD)
            self._lbl[key] = v

        # rDNS with loading state
        rdns_row = tk.Frame(left_col, bg=BG_CARD)
        rdns_row.pack(fill="x", pady=1)
        tk.Label(rdns_row, text="Reverse DNS", bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_SMALL, width=18, anchor="w").pack(side="left")
        self._rdns_label = tk.Label(rdns_row, text="—", bg=BG_CARD,
                                     fg=FG_PRIMARY, font=FONT_MONO, anchor="w")
        self._rdns_label.pack(side="left", fill="x", expand=True)

        self._rdns_note = tk.Label(
            left_col,
            text="⚠ rDNS is set by the IP owner and is not independently verified.",
            bg=BG_CARD, fg=FG_MUTED, font=FONT_SMALL,
            wraplength=240, justify="left", anchor="w"
        )
        self._rdns_note.pack(anchor="w", pady=(4, 0))

        # Right column fields — session stats
        section_header(right_col, "SESSION ACTIVITY", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_TINY)
        )
        right_fields = [
            ("packets",    "Packets"),
            ("flows",      "Flows"),
            ("bytes",      "Total Bytes"),
            ("payload",    "Payload Bytes"),
            ("outbound",   "Outbound Pkts"),
            ("inbound",    "Inbound Pkts"),
            ("protocols",  "Protocols"),
            ("first_seen", "First Seen"),
            ("last_seen",  "Last Seen"),
        ]
        for key, label in right_fields:
            _, v = detail_row(right_col, label, "—", bg=BG_CARD)
            self._lbl[key] = v

        # Ports
        _, v = detail_row(right_col, "Ports Contacted", "—", bg=BG_CARD)
        self._lbl["ports"] = v

        horizontal_separator(p, bg=BG_CARD).pack(fill="x", padx=PAD_INNER,
                                                   pady=PAD_SMALL)

        # ── Actions ───────────────────────────────────────────────────────────
        actions = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER)
        actions.pack(fill="x")

        section_header(actions, "ACTIONS", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        btn_row = tk.Frame(actions, bg=BG_CARD)
        btn_row.pack(fill="x")

        DarkButton(btn_row, "VIEW TRAFFIC",
                   command=self._view_traffic).pack(side="left", padx=(0, 2))
        DarkButton(btn_row, "VIEW FLOWS",
                   command=self._view_flows).pack(side="left", padx=2)
        DarkButton(btn_row, "ADD NOTE",
                   command=self._add_note).pack(side="left", padx=2)

        import config.settings as _settings
        if _settings.get("enable_firewall_controls"):
            DarkButton(btn_row, "BLOCK IP",
                       command=self._block_ip,
                       danger=True).pack(side="left", padx=2)

        horizontal_separator(p, bg=BG_CARD).pack(fill="x", padx=PAD_INNER,
                                                   pady=PAD_SMALL)

        # ── Related flows mini-table ──────────────────────────────────────────
        section_header(p, "RELATED FLOWS", bg=BG_CARD).pack(
            fill="x", padx=PAD_INNER, pady=(0, PAD_TINY)
        )

        flow_frame = tk.Frame(p, bg=BG_CARD)
        flow_frame.pack(fill="x", padx=PAD_INNER)

        mini_cols = ("PROTOCOL", "REMOTE IP", "PORT", "PACKETS", "BYTES", "RISK")
        self._flow_mini = ttk.Treeview(
            flow_frame, columns=mini_cols, show="headings", height=6
        )
        col_widths = {"PROTOCOL": 70, "REMOTE IP": 130, "PORT": 60,
                      "PACKETS": 70, "BYTES": 80, "RISK": 70}
        for col in mini_cols:
            self._flow_mini.heading(col, text=col)
            self._flow_mini.column(col, width=col_widths.get(col, 70), anchor="w")

        mini_scroll = ttk.Scrollbar(flow_frame, orient="vertical",
                                     command=self._flow_mini.yview)
        self._flow_mini.configure(yscrollcommand=mini_scroll.set)
        mini_scroll.pack(side="right", fill="y")
        self._flow_mini.pack(fill="x")

        self._selected_ip: str = ""

    # ── Data Population ───────────────────────────────────────────────────────

    def _populate_ip_list(self) -> None:
        """Fill the IP list with all session IPs."""
        self._ip_list.delete(*self._ip_list.get_children())

        ips = self._get_filtered_ips()

        # Pre-classify all IPs (fast, no network calls)
        packet_counts: dict[str, int] = {}
        for p in self._packets:
            for key in ("src_ip", "dst_ip"):
                ip = p.get(key)
                if ip:
                    packet_counts[ip] = packet_counts.get(ip, 0) + 1

        for i, ip in enumerate(ips):
            info = classify_ip(ip)
            ip_type = info.get("ip_type", "UNKNOWN")
            count   = packet_counts.get(ip, 0)
            tag     = ip_type if ip_type in ("PUBLIC", "PRIVATE", "LOOPBACK") else "even"

            self._ip_list.insert(
                "", "end", iid=ip,
                values=(ip, ip_type, f"{count:,}"),
                tags=(tag,),
            )

        self._status_bar.set_status(
            f"Showing {len(ips):,} of {len(self._all_ips):,} IPs", "idle"
        )

    def _get_filtered_ips(self) -> list[str]:
        """Apply current filter text and type filter."""
        text    = self._filter_var.get().lower().strip()
        ips     = self._all_ips

        if text:
            ips = [ip for ip in ips if text in ip]

        if self._type_filter != "ALL":
            ips = [
                ip for ip in ips
                if classify_ip(ip).get("ip_type") == self._type_filter
            ]

        return ips

    def _select_ip(self, ip: str) -> None:
        """Programmatically select an IP in the list and show its details."""
        if ip in self._ip_list.get_children():
            self._ip_list.selection_set(ip)
            self._ip_list.see(ip)
        self._load_ip_details(ip)

    def _on_ip_list_select(self, event) -> None:
        sel = self._ip_list.selection()
        if sel:
            self._load_ip_details(sel[0])

    def _load_ip_details(self, ip: str) -> None:
        """Load classification, rDNS, and session stats for one IP."""
        self._selected_ip = ip

        # Update header immediately
        self._ip_display.configure(text=ip)
        self._rdns_label.configure(text="looking up…", fg=FG_SECONDARY)

        # Use cache if available
        if ip in self._cache:
            cached = self._cache[ip]
            self._display_ip_details(cached["info"], cached["rdns"],
                                     cached["summary"])
            return

        # Classify (fast, synchronous)
        info    = classify_ip(ip)
        summary = build_ip_summary(ip, self._packets, self._flows)

        # Update all fields except rDNS (which takes time)
        self._display_ip_details(info, "(looking up…)", summary)

        # rDNS in background thread so GUI stays responsive
        def do_rdns():
            rdns = reverse_dns_lookup(ip)
            # Cache the result
            self._cache[ip] = {"info": info, "rdns": rdns, "summary": summary}
            # Update UI on main thread
            if self.window.winfo_exists() and self._selected_ip == ip:
                self.window.after(0, lambda: self._update_rdns_label(rdns))

        threading.Thread(target=do_rdns, daemon=True, name="rDNS").start()

    def _display_ip_details(self, info: dict, rdns: str, summary: dict) -> None:
        """Populate all detail panel fields."""
        ip_type = info.get("ip_type", "—")
        color   = {
            "PUBLIC":    FG_ACCENT,
            "PRIVATE":   FG_SUCCESS,
            "LOOPBACK":  FG_MUTED,
            "MULTICAST": FG_WARNING,
        }.get(ip_type, FG_SECONDARY)

        self._ip_type_badge.configure(text=ip_type, fg=color)
        self._ip_desc_label.configure(text=info.get("description", ""))

        # Network fields
        self._lbl["version"].configure(
            text=f"IPv{info.get('version', '?')}")
        self._lbl["ip_type"].configure(text=ip_type, fg=color)
        self._lbl["net_class"].configure(
            text=info.get("network_class", "—"))
        self._lbl["is_private"].configure(
            text="Yes" if info.get("is_private") else "No")
        self._lbl["is_global"].configure(
            text="Yes" if info.get("is_global") else "No")

        # Session activity
        self._lbl["packets"].configure(
            text=f"{summary.get('packet_count', 0):,}")
        self._lbl["flows"].configure(
            text=f"{summary.get('flow_count', 0):,}")
        self._lbl["bytes"].configure(
            text=format_bytes(summary.get("total_bytes", 0)))
        self._lbl["payload"].configure(
            text=format_bytes(summary.get("total_payload", 0)))
        self._lbl["outbound"].configure(
            text=f"{summary.get('outbound_packets', 0):,}")
        self._lbl["inbound"].configure(
            text=f"{summary.get('inbound_packets', 0):,}")
        self._lbl["protocols"].configure(
            text=summary.get("protocols", "—"))
        self._lbl["first_seen"].configure(
            text=summary.get("first_seen", "—"))
        self._lbl["last_seen"].configure(
            text=summary.get("last_seen", "—"))

        ports = summary.get("dst_ports", [])
        ports_text = ", ".join(str(p) for p in ports[:10])
        if len(ports) > 10:
            ports_text += f"  (+{len(ports)-10} more)"
        self._lbl["ports"].configure(text=ports_text or "—")

        # rDNS (may still be loading)
        self._rdns_label.configure(text=rdns or "(not found)", fg=FG_PRIMARY)

        # Related flows mini-table
        self._flow_mini.delete(*self._flow_mini.get_children())
        selected_ip = info.get("address", "")

        for flow in summary.get("related_flows", [])[:30]:
            # Show the "remote" endpoint from this IP's perspective
            if flow.get("src_ip") == selected_ip:
                remote_ip   = flow.get("dst_ip", "?")
                remote_port = flow.get("dst_port", "?")
            else:
                remote_ip   = flow.get("src_ip", "?")
                remote_port = flow.get("src_port", "?")

            self._flow_mini.insert("", "end", values=(
                flow.get("protocol", "?"),
                remote_ip,
                remote_port,
                f"{flow.get('packet_count', 0):,}",
                format_bytes(flow.get("byte_count", 0)),
                flow.get("risk_level", "NONE"),
            ))

        self._status_bar.set_status(
            f"Loaded details for {info.get('address', '')}", "idle"
        )

    def _update_rdns_label(self, rdns: str) -> None:
        """Called on main thread when background rDNS lookup completes."""
        text = rdns if rdns else "(no PTR record found)"
        self._rdns_label.configure(text=text, fg=FG_PRIMARY)

    # ── Filter / Actions ──────────────────────────────────────────────────────

    def _apply_list_filter(self) -> None:
        self._populate_ip_list()

    def _quick_type_filter(self, type_label: str) -> None:
        self._type_filter = type_label
        self._populate_ip_list()

    def _lookup_manual(self) -> None:
        """Look up an IP the analyst typed manually (may not be in session)."""
        ip = self._lookup_var.get().strip()
        if not ip:
            return

        # Add to all_ips if not already there so the list shows it
        if ip not in self._all_ips:
            self._all_ips.append(ip)
            self._populate_ip_list()

        self._select_ip(ip)

    def _view_traffic(self) -> None:
        if not self._selected_ip:
            return
        messagebox.showinfo(
            "Filter Tip",
            f"In the Capture window, set the filter to:\n\n"
            f"    {self._selected_ip}\n\n"
            "to see all traffic for this IP.",
            parent=self.window
        )

    def _view_flows(self) -> None:
        if not self._selected_ip:
            return
        from ui.flow_window import FlowWindow
        FlowWindow(self.window, self.session_id,
                   self._packets, self._flows)

    def _block_ip(self) -> None:
        """Open the firewall block confirmation dialog."""
        if not self._selected_ip:
            return
        from ui.firewall_dialog import FirewallBlockDialog
        FirewallBlockDialog(
            self.window,
            ip_address=self._selected_ip,
            on_confirm=lambda ip, d, r: self._status_bar.set_status(
                f"Block rule created for {ip} ({d})", "idle"
            )
        )

    def _add_note(self) -> None:
        if not self._selected_ip:
            return
        from ui.flow_window import _NoteDialog
        _NoteDialog(self.window, self.session_id, "ip", self._selected_ip)
