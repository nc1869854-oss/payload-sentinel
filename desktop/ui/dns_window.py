"""
ui/dns_window.py

DNS Analysis window.

DNS is one of the most investigation-relevant protocols — beaconing,
tunnelling, DGA malware, and data exfiltration all leave distinct DNS
patterns.  This window surfaces those patterns without claiming to
confirm malicious behaviour.

Columns:
    TIME  CLIENT  QUERY  TYPE  RESPONSE  RESULT

Analysis signals shown:
    • query frequency per client
    • unique domain count
    • NXDOMAIN rate
    • long domain names (>50 chars)
    • repeated identical queries
    • fast succession (same query < 2 s apart)
"""

import tkinter as tk
from tkinter import ttk
from collections import Counter, defaultdict

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_WARNING, FG_DANGER, FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
)
from ui.widgets import (
    DarkButton, StatusBar, horizontal_separator, section_header, detail_row,
)
from config.logger import get_logger

log = get_logger(__name__)

# Threshold for flagging a domain name as "unusually long"
LONG_DOMAIN_THRESHOLD = 50


class DnsWindow:
    """
    DNS Analysis workstation.

    Parameters
    ----------
    parent     : Tk root window
    session_id : active session
    packets    : full parsed packet list (we filter DNS ourselves)
    """

    def __init__(self, parent: tk.Tk, session_id: str, packets: list[dict]):
        self.parent     = parent
        self.session_id = session_id
        self._all_packets = packets

        # Build DNS-only dataset once
        self._dns_packets = [p for p in packets if p.get("is_dns")]

        self.window = tk.Toplevel(parent)
        self.window.title("DNS Analysis")
        self.window.geometry("1100x680")
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

        self._build_ui()
        self._populate()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        horizontal_separator(self.window).pack(fill="x")

        body = tk.Frame(self.window, bg=BG_DARK)
        body.pack(fill="both", expand=True)

        self._build_table(body)
        self._build_analysis_panel(body)

        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

    def _build_header(self) -> None:
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        left = tk.Frame(header, bg=BG_CARD)
        left.pack(side="left")
        tk.Label(left, text="DNS ANALYSIS", bg=BG_CARD,
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(left,
                 text="Query activity · frequency · anomaly signals",
                 bg=BG_CARD, fg=FG_SECONDARY, font=FONT_SMALL).pack(anchor="w")

        right = tk.Frame(header, bg=BG_CARD)
        right.pack(side="right")

        # Filter bar
        tk.Label(right, text="FILTER:", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_LABEL).pack(side="left")
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        ttk.Entry(right, textvariable=self._filter_var, width=25).pack(
            side="left", padx=PAD_SMALL)
        DarkButton(right, "CLEAR FILTER",
                   command=lambda: self._filter_var.set("")
                   ).pack(side="left")

    def _build_table(self, parent: tk.Frame) -> None:
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(side="left", fill="both", expand=True)

        cols = ("TIME", "CLIENT", "QUERY", "RESPONSE", "PKT #")
        widths = {"TIME": 80, "CLIENT": 120, "QUERY": 280,
                  "RESPONSE": 130, "PKT #": 65}

        self._tree = ttk.Treeview(frame, columns=cols,
                                   show="headings", selectmode="browse")
        for col in cols:
            self._tree.heading(col, text=col, anchor="w",
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=widths.get(col, 80),
                              minwidth=40, anchor="w")

        self._tree.tag_configure("even",       background="#161b22")
        self._tree.tag_configure("odd",        background="#1c2128")
        self._tree.tag_configure("long_domain",foreground=FG_WARNING)
        self._tree.tag_configure("repeated",   foreground=FG_ACCENT)

        scroll_y = ttk.Scrollbar(frame, orient="vertical",
                                  command=self._tree.yview)
        scroll_x = ttk.Scrollbar(frame, orient="horizontal",
                                  command=self._tree.xview)
        self._tree.configure(yscrollcommand=scroll_y.set,
                             xscrollcommand=scroll_x.set)
        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)

        self._tree.bind("<<TreeviewSelect>>", self._on_row_selected)

        self._sort_col = "TIME"
        self._sort_asc = True

    def _build_analysis_panel(self, parent: tk.Frame) -> None:
        panel = tk.Frame(parent, bg=BG_CARD, width=300)
        panel.pack(side="right", fill="y")
        panel.pack_propagate(False)

        # ── Summary stats ────────────────────────────────────────────────────
        stats = tk.Frame(panel, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        stats.pack(fill="x")

        section_header(stats, "DNS STATISTICS", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL))

        self._stat_labels: dict[str, tk.Label] = {}
        for key, label in [
            ("total_queries",   "Total DNS Packets"),
            ("unique_domains",  "Unique Domains"),
            ("unique_clients",  "Unique Clients"),
            ("long_domains",    "Long Domains (>50 chars)"),
            ("repeated_queries","Repeated Queries"),
        ]:
            _, v = detail_row(stats, label, "—", bg=BG_CARD)
            self._stat_labels[key] = v

        horizontal_separator(panel, bg=BG_CARD).pack(
            fill="x", pady=PAD_SMALL)

        # ── Top queried domains ───────────────────────────────────────────────
        section_header(panel, "TOP QUERIED DOMAINS",
                        bg=BG_CARD).pack(fill="x", padx=PAD_INNER,
                                          pady=(0, PAD_SMALL))

        self._top_domains_frame = tk.Frame(panel, bg=BG_CARD)
        self._top_domains_frame.pack(fill="x", padx=PAD_INNER)

        horizontal_separator(panel, bg=BG_CARD).pack(
            fill="x", pady=PAD_SMALL)

        # ── Investigation signals ─────────────────────────────────────────────
        section_header(panel, "INVESTIGATION SIGNALS",
                        bg=BG_CARD).pack(fill="x", padx=PAD_INNER,
                                          pady=(0, PAD_SMALL))

        self._signals_frame = tk.Frame(panel, bg=BG_CARD)
        self._signals_frame.pack(fill="x", padx=PAD_INNER)

        horizontal_separator(panel, bg=BG_CARD).pack(
            fill="x", pady=PAD_SMALL)

        # ── Selected query detail ─────────────────────────────────────────────
        section_header(panel, "SELECTED QUERY",
                        bg=BG_CARD).pack(fill="x", padx=PAD_INNER,
                                          pady=(0, PAD_SMALL))

        detail_frame = tk.Frame(panel, bg=BG_CARD, padx=PAD_INNER)
        detail_frame.pack(fill="x")

        self._detail_labels: dict[str, tk.Label] = {}
        for key, label in [
            ("time",      "Time"),
            ("client",    "Client"),
            ("query",     "Query"),
            ("response",  "Response"),
            ("pkt",       "Packet #"),
            ("query_len", "Domain Length"),
        ]:
            _, v = detail_row(detail_frame, label, "—", bg=BG_CARD)
            self._detail_labels[key] = v

    # ── Data ─────────────────────────────────────────────────────────────────

    def _populate(self) -> None:
        self._rebuild_table(self._dns_packets)
        self._rebuild_analysis(self._dns_packets)

    def _rebuild_table(self, packets: list[dict]) -> None:
        self._tree.delete(*self._tree.get_children())

        if not packets:
            self._tree.insert("", "end", values=(
                "", "", "(no DNS packets in session)", "", ""
            ))
            self._status_bar.set_status("No DNS packets found", "idle")
            return

        query_counts = Counter(
            p.get("dns_query", "") for p in self._all_packets
            if p.get("is_dns") and p.get("dns_query")
        )

        for i, p in enumerate(packets):
            query     = p.get("dns_query") or "—"
            response  = p.get("dns_response") or "—"
            time_str  = (p.get("capture_time") or "")[-12:-3]
            client    = p.get("src_ip") or "—"
            pkt_num   = p.get("packet_number", "")

            # Choose row tag based on signals
            if query != "—" and len(query) > LONG_DOMAIN_THRESHOLD:
                tag = "long_domain"
            elif query != "—" and query_counts.get(query, 0) > 5:
                tag = "repeated"
            else:
                tag = "even" if i % 2 == 0 else "odd"

            self._tree.insert("", "end", iid=str(i), values=(
                time_str, client, query, response, pkt_num,
            ), tags=(tag,))

        self._status_bar.set_status(
            f"DNS packets: {len(packets):,}", "idle"
        )

    def _rebuild_analysis(self, packets: list[dict]) -> None:
        # Stats
        queries = [p.get("dns_query") for p in packets if p.get("dns_query")]
        clients = [p.get("src_ip")    for p in packets if p.get("src_ip")]
        query_counts = Counter(queries)
        repeated = sum(1 for c in query_counts.values() if c > 1)
        long_domains = sum(1 for q in queries if len(q) > LONG_DOMAIN_THRESHOLD)

        self._stat_labels["total_queries"].configure(text=f"{len(packets):,}")
        self._stat_labels["unique_domains"].configure(
            text=f"{len(set(queries)):,}")
        self._stat_labels["unique_clients"].configure(
            text=f"{len(set(clients)):,}")
        self._stat_labels["long_domains"].configure(
            text=f"{long_domains:,}",
            fg=FG_WARNING if long_domains else FG_PRIMARY)
        self._stat_labels["repeated_queries"].configure(
            text=f"{repeated:,}",
            fg=FG_ACCENT if repeated else FG_PRIMARY)

        # Top domains
        for w in self._top_domains_frame.winfo_children():
            w.destroy()

        for domain, count in query_counts.most_common(8):
            row = tk.Frame(self._top_domains_frame, bg=BG_CARD)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=domain[:32], bg=BG_CARD, fg=FG_PRIMARY,
                     font=FONT_MONO, anchor="w").pack(side="left")
            tk.Label(row, text=f"  ×{count}", bg=BG_CARD, fg=FG_SECONDARY,
                     font=FONT_SMALL, anchor="e").pack(side="right")

        if not query_counts:
            tk.Label(self._top_domains_frame,
                     text="(no queries)", bg=BG_CARD,
                     fg=FG_MUTED, font=FONT_SMALL).pack(anchor="w")

        # Investigation signals
        for w in self._signals_frame.winfo_children():
            w.destroy()

        signals = self._compute_signals(packets, query_counts)
        if not signals:
            tk.Label(self._signals_frame,
                     text="No signals detected.",
                     bg=BG_CARD, fg=FG_MUTED, font=FONT_SMALL).pack(anchor="w")
        else:
            for sig in signals:
                color = FG_WARNING if sig["level"] == "MEDIUM" else FG_ACCENT
                row = tk.Frame(self._signals_frame, bg=BG_CARD)
                row.pack(fill="x", pady=2)
                tk.Label(row, text="•", bg=BG_CARD, fg=color,
                         font=FONT_SMALL).pack(side="left", padx=(0, 4))
                tk.Label(row, text=sig["text"], bg=BG_CARD,
                         fg=FG_PRIMARY, font=FONT_SMALL,
                         wraplength=240, justify="left",
                         anchor="w").pack(side="left", fill="x")

    def _compute_signals(self, packets: list[dict],
                          query_counts: Counter) -> list[dict]:
        signals = []

        # High overall DNS volume
        if len(packets) >= 100:
            signals.append({
                "level": "MEDIUM",
                "text": f"{len(packets):,} DNS packets — above normal for most hosts"
            })

        # Long domain names
        long = [q for q in query_counts if len(q) > LONG_DOMAIN_THRESHOLD]
        if long:
            signals.append({
                "level": "MEDIUM",
                "text": f"{len(long)} domain(s) exceed {LONG_DOMAIN_THRESHOLD} chars "
                        f"(potential DGA or DNS tunnelling signal)"
            })

        # Single domain queried many times
        for domain, count in query_counts.most_common(3):
            if count >= 20:
                signals.append({
                    "level": "LOW",
                    "text": f"'{domain[:30]}' queried {count}× — "
                            f"may indicate beaconing or misconfiguration"
                })

        # Many unique domains from one client
        client_domains: dict[str, set] = defaultdict(set)
        for p in packets:
            if p.get("dns_query") and p.get("src_ip"):
                client_domains[p["src_ip"]].add(p["dns_query"])

        for client, domains in client_domains.items():
            if len(domains) >= 30:
                signals.append({
                    "level": "MEDIUM",
                    "text": f"{client} queried {len(domains)} unique domains "
                            f"— review for DGA patterns"
                })

        return signals

    # ── Interactions ──────────────────────────────────────────────────────────

    def _on_row_selected(self, event) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        filtered = self._get_filtered()
        if idx >= len(filtered):
            return
        p = filtered[idx]
        query = p.get("dns_query") or "—"
        self._detail_labels["time"].configure(
            text=(p.get("capture_time") or "")[-12:-3])
        self._detail_labels["client"].configure(
            text=p.get("src_ip") or "—")
        self._detail_labels["query"].configure(text=query)
        self._detail_labels["response"].configure(
            text=p.get("dns_response") or "—")
        self._detail_labels["pkt"].configure(
            text=str(p.get("packet_number", "—")))
        self._detail_labels["query_len"].configure(
            text=f"{len(query)} chars" if query != "—" else "—",
            fg=FG_WARNING if query != "—" and len(query) > LONG_DOMAIN_THRESHOLD
               else FG_PRIMARY)

    def _get_filtered(self) -> list[dict]:
        text = self._filter_var.get().lower().strip()
        if not text:
            return self._dns_packets
        return [
            p for p in self._dns_packets
            if text in (p.get("dns_query") or "").lower()
            or text in (p.get("src_ip") or "").lower()
            or text in (p.get("dns_response") or "").lower()
        ]

    def _apply_filter(self) -> None:
        filtered = self._get_filtered()
        self._rebuild_table(filtered)
        self._rebuild_analysis(filtered)

    def _sort_by(self, column: str) -> None:
        if self._sort_col == column:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = column
            self._sort_asc = True
        self._apply_filter()
