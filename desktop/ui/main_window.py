"""
ui/main_window.py

Main application window — the investigation dashboard.

Answers five questions immediately on open:
  1. WHAT IS HAPPENING?         → session status bar + source label
  2. HOW MUCH TRAFFIC?          → four metric cards (packets/flows/payload/bytes)
  3. WHAT IS UNUSUAL?           → priority findings panel (live count by severity)
  4. WHAT SHOULD I INVESTIGATE? → recent timeline events panel
  5. WHAT EVIDENCE DO I HAVE?   → session panel shows notes/evidence count

All module windows are launched from the bottom toolbar.
Session lifecycle (new / open / close) is in the header.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from config.theme import (
    BG_DARK, BG_CARD, BG_HEADER,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_WARNING, FG_MUTED,
    FONT_HEADER, FONT_SUBHEADER, FONT_BODY, FONT_CARD_TITLE,
    FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
    MAIN_WINDOW_SIZE, SEVERITY_COLORS,
)
from ui.widgets import (
    apply_dark_theme, DarkButton, MetricCard,
    StatusBar, horizontal_separator,
)
from evidence import database as db
from evidence.sessions import format_bytes
from core.session import InvestigationSession, SessionStatus
from config.logger import get_logger

log = get_logger(__name__)


class MainWindow:
    """
    Root application window — investigation command centre.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Payload Capture Suite — Network Investigation & Evidence Platform")
        self.root.geometry(MAIN_WINDOW_SIZE)
        self.root.configure(bg=BG_DARK)
        self.root.resizable(True, True)
        self.root.minsize(960, 620)

        apply_dark_theme(root)

        # Active session
        self._session: InvestigationSession | None = None
        self._capture_window = None

        self._build_ui()
        self._tick()   # start the 1-second clock

        # Register safe-shutdown so a capture in progress is stopped cleanly
        # before the window is destroyed.
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        self._build_metric_row()
        self._build_session_bar()

        # Middle body — two columns
        body = tk.Frame(self.root, bg=BG_DARK)
        body.pack(fill="both", expand=True, padx=PAD_OUTER, pady=(0, PAD_SMALL))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_findings_panel(body)
        self._build_timeline_panel(body)

        self._build_module_toolbar()

        self._status_bar = StatusBar(self.root)
        self._status_bar.pack(side="bottom", fill="x")
        self._status_bar.set_status("Ready — create or open a session to begin", "idle")

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=BG_HEADER, pady=PAD_SMALL)
        header.pack(fill="x")

        # Left — branding
        left = tk.Frame(header, bg=BG_HEADER)
        left.pack(side="left", padx=PAD_OUTER)

        tk.Label(left, text="PAYLOAD CAPTURE SUITE",
                 bg=BG_HEADER, fg=FG_ACCENT,
                 font=FONT_HEADER).pack(anchor="w")
        tk.Label(left, text="Network Investigation & Evidence Platform",
                 bg=BG_HEADER, fg=FG_SECONDARY,
                 font=FONT_SUBHEADER).pack(anchor="w")

        # Right — system status + session controls
        right = tk.Frame(header, bg=BG_HEADER)
        right.pack(side="right", padx=PAD_OUTER)

        self._system_label = tk.Label(
            right, text="● SYSTEM READY",
            bg=BG_HEADER, fg=FG_SUCCESS, font=FONT_BODY
        )
        self._system_label.pack(anchor="e")

        btn_row = tk.Frame(right, bg=BG_HEADER)
        btn_row.pack(anchor="e", pady=(6, 0))

        DarkButton(btn_row, "NEW SESSION",
                   command=self._new_session, accent=True
                   ).pack(side="left", padx=2)
        DarkButton(btn_row, "OPEN SESSION",
                   command=self._open_session
                   ).pack(side="left", padx=2)
        DarkButton(btn_row, "CLOSE SESSION",
                   command=self._close_session
                   ).pack(side="left", padx=2)
        DarkButton(btn_row, "SETTINGS",
                   command=self._open_settings
                   ).pack(side="left", padx=2)
        DarkButton(btn_row, "ABOUT & LEGAL",
                   command=self._open_about
                   ).pack(side="left", padx=2)

        horizontal_separator(self.root).pack(fill="x")

    # ── Metric cards ──────────────────────────────────────────────────────────

    def _build_metric_row(self) -> None:
        row = tk.Frame(self.root, bg=BG_DARK, pady=PAD_SMALL)
        row.pack(fill="x", padx=PAD_OUTER)

        self._card_packets  = MetricCard(row, "PACKETS",  "—", FG_ACCENT)
        self._card_flows    = MetricCard(row, "FLOWS",    "—", FG_SUCCESS)
        self._card_payload  = MetricCard(row, "PAYLOAD",  "—", FG_PRIMARY)
        self._card_findings = MetricCard(row, "FINDINGS", "—", FG_WARNING)

        for card in (self._card_packets, self._card_flows,
                     self._card_payload, self._card_findings):
            card.pack(side="left", padx=(0, PAD_SMALL),
                      expand=True, fill="x")

        horizontal_separator(self.root).pack(
            fill="x", padx=PAD_OUTER, pady=(PAD_SMALL, 0))

    # ── Session info bar ──────────────────────────────────────────────────────

    def _build_session_bar(self) -> None:
        bar = tk.Frame(self.root, bg=BG_CARD,
                       padx=PAD_INNER, pady=PAD_SMALL)
        bar.pack(fill="x", padx=PAD_OUTER, pady=PAD_SMALL)

        tk.Label(bar, text="CURRENT INVESTIGATION",
                 bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_CARD_TITLE).pack(side="left", padx=(0, PAD_OUTER))

        self._sess_id_lbl = tk.Label(
            bar, text="Session: —",
            bg=BG_CARD, fg=FG_PRIMARY, font=FONT_BODY)
        self._sess_id_lbl.pack(side="left", padx=(0, PAD_OUTER))

        self._sess_src_lbl = tk.Label(
            bar, text="Source: —",
            bg=BG_CARD, fg=FG_SECONDARY, font=FONT_BODY)
        self._sess_src_lbl.pack(side="left", padx=(0, PAD_OUTER))

        self._sess_dur_lbl = tk.Label(
            bar, text="Duration: —",
            bg=BG_CARD, fg=FG_SECONDARY, font=FONT_BODY)
        self._sess_dur_lbl.pack(side="left", padx=(0, PAD_OUTER))

        self._sess_status_lbl = tk.Label(
            bar, text="NO ACTIVE SESSION",
            bg=BG_CARD, fg=FG_MUTED, font=FONT_BODY)
        self._sess_status_lbl.pack(side="right")

        horizontal_separator(self.root).pack(
            fill="x", padx=PAD_OUTER, pady=(0, PAD_SMALL))

    # ── Priority findings panel ───────────────────────────────────────────────

    def _build_findings_panel(self, parent: tk.Frame) -> None:
        """Left column — priority findings by severity."""
        frame = tk.Frame(parent, bg=BG_CARD,
                         padx=PAD_INNER, pady=PAD_INNER)
        frame.grid(row=0, column=0, sticky="nsew",
                   padx=(0, PAD_SMALL), pady=0)

        header = tk.Frame(frame, bg=BG_CARD)
        header.pack(fill="x", pady=(0, PAD_SMALL))

        tk.Label(header, text="PRIORITY FINDINGS",
                 bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_CARD_TITLE).pack(side="left")

        DarkButton(header, "OPEN ALERTS",
                   command=self._open_alerts
                   ).pack(side="right")

        # Severity breakdown rows
        sev_frame = tk.Frame(frame, bg=BG_CARD)
        sev_frame.pack(fill="x")

        self._sev_labels: dict[str, tk.Label] = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            row = tk.Frame(sev_frame, bg=BG_CARD)
            row.pack(fill="x", pady=2)

            color = SEVERITY_COLORS.get(sev, FG_SECONDARY)
            tk.Label(row, text=f"● {sev}", bg=BG_CARD, fg=color,
                     font=FONT_BODY, width=12, anchor="w").pack(side="left")

            val = tk.Label(row, text="—", bg=BG_CARD,
                           fg=FG_PRIMARY, font=FONT_MONO, anchor="w")
            val.pack(side="left")
            self._sev_labels[sev] = val

        horizontal_separator(frame, bg=BG_CARD).pack(
            fill="x", pady=PAD_SMALL)

        # Recent findings list
        tk.Label(frame, text="RECENT FINDINGS",
                 bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_CARD_TITLE).pack(anchor="w",
                                             pady=(0, PAD_SMALL))

        cols = ("SEV", "TITLE", "STATE")
        self._findings_tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            height=6, selectmode="browse")
        self._findings_tree.heading("SEV",   text="SEV")
        self._findings_tree.heading("TITLE", text="TITLE")
        self._findings_tree.heading("STATE", text="STATE")
        self._findings_tree.column("SEV",   width=65,  anchor="w")
        self._findings_tree.column("TITLE", width=230, anchor="w")
        self._findings_tree.column("STATE", width=90,  anchor="w")

        for sev, color in SEVERITY_COLORS.items():
            self._findings_tree.tag_configure(sev, foreground=color)

        self._findings_tree.pack(fill="both", expand=True)
        self._findings_tree.bind("<Double-1>", lambda e: self._open_alerts())

        # Empty state
        self._findings_empty = tk.Label(
            frame,
            text="NO FINDINGS\n\nRun analysis after capture to generate findings.",
            bg=BG_CARD, fg=FG_MUTED, font=FONT_SMALL,
            justify="center")

    # ── Timeline preview panel ────────────────────────────────────────────────

    def _build_timeline_panel(self, parent: tk.Frame) -> None:
        """Right column — recent timeline events."""
        frame = tk.Frame(parent, bg=BG_CARD,
                         padx=PAD_INNER, pady=PAD_INNER)
        frame.grid(row=0, column=1, sticky="nsew", pady=0)

        header = tk.Frame(frame, bg=BG_CARD)
        header.pack(fill="x", pady=(0, PAD_SMALL))

        tk.Label(header, text="INVESTIGATION TIMELINE",
                 bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_CARD_TITLE).pack(side="left")

        DarkButton(header, "OPEN TIMELINE",
                   command=self._open_timeline
                   ).pack(side="right")

        # Event list
        cols = ("TIME", "TYPE", "DESCRIPTION")
        self._timeline_tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            height=10, selectmode="browse")
        self._timeline_tree.heading("TIME", text="TIME")
        self._timeline_tree.heading("TYPE", text="TYPE")
        self._timeline_tree.heading("DESCRIPTION", text="DESCRIPTION")
        self._timeline_tree.column("TIME",        width=70,  anchor="w")
        self._timeline_tree.column("TYPE",        width=75,  anchor="w")
        self._timeline_tree.column("DESCRIPTION", width=280, anchor="w")

        from config.theme import FG_ACCENT, FG_SUCCESS
        self._timeline_tree.tag_configure("DNS",    foreground=FG_ACCENT)
        self._timeline_tree.tag_configure("TCP",    foreground=FG_SUCCESS)
        self._timeline_tree.tag_configure("TLS",    foreground="#d2a8ff")
        self._timeline_tree.tag_configure("UDP",    foreground="#58a6ff")
        self._timeline_tree.tag_configure("ACTION", foreground=FG_WARNING)
        self._timeline_tree.tag_configure("even",   background="#161b22")
        self._timeline_tree.tag_configure("odd",    background="#1c2128")

        scroll = ttk.Scrollbar(frame, orient="vertical",
                               command=self._timeline_tree.yview)
        self._timeline_tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self._timeline_tree.pack(fill="both", expand=True)

        # Empty state
        self._timeline_empty = tk.Label(
            frame,
            text="NO TIMELINE EVENTS\n\nCapture traffic to populate the timeline.",
            bg=BG_CARD, fg=FG_MUTED, font=FONT_SMALL,
            justify="center")

    # ── Module toolbar ────────────────────────────────────────────────────────

    def _build_module_toolbar(self) -> None:
        """Bottom toolbar with all module launchers."""
        horizontal_separator(self.root).pack(fill="x", padx=PAD_OUTER)

        toolbar = tk.Frame(self.root, bg=BG_CARD, pady=PAD_SMALL)
        toolbar.pack(fill="x")

        buttons = [
            ("CAPTURE",     self._open_capture),
            ("FLOWS",       self._open_flows),
            ("DNS",         self._open_dns),
            ("ALERTS",      self._open_alerts),
            ("TIMELINE",    self._open_timeline),
            ("IP ANALYSIS", self._open_ip),
            ("EVIDENCE",    self._open_reports),
            ("SEARCH",      self._open_search),
            ("AUDIT TRAIL", self._open_audit),
            ("ABOUT & LEGAL", self._open_about),
        ]

        for label, cmd in buttons:
            DarkButton(toolbar, label, command=cmd,
                       accent=(label == "CAPTURE")
                       ).pack(side="left", padx=4, pady=2)

    # ── Session Lifecycle ─────────────────────────────────────────────────────

    def _new_session(self) -> None:
        if self._session:
            if not messagebox.askyesno(
                "New Session",
                "A session is already active. Close it and start a new one?",
                parent=self.root
            ):
                return
            self._close_session(confirm=False)

        self._session = InvestigationSession.create(analyst="Analyst")
        self._session.subscribe(self._on_session_update)
        self._refresh_session_display()
        db.log_action(self._session.session_id, "SESSION_CREATED")
        self._status_bar.set_status(
            f"Session {self._session.session_id} created", "active")
        log.info("New session: %s", self._session.session_id)

    def _open_session(self) -> None:
        sessions = db.get_all_sessions()
        if not sessions:
            messagebox.showinfo("No Sessions",
                                "No previous sessions found.",
                                parent=self.root)
            return
        _SessionPickerDialog(self.root, sessions, self._load_session)

    def _load_session(self, session_id: str) -> None:
        self._session = InvestigationSession.load(session_id)
        if not self._session:
            messagebox.showerror("Error",
                                 f"Could not load session {session_id}.",
                                 parent=self.root)
            return
        self._session.subscribe(self._on_session_update)
        self._refresh_session_display()
        self._refresh_findings_panel()
        self._refresh_timeline_panel()
        self._status_bar.set_status(f"Session {session_id} loaded", "idle")
        log.info("Session loaded: %s", session_id)

    def _close_session(self, confirm: bool = True) -> None:
        if not self._session:
            messagebox.showinfo("No Session",
                                "No active session.", parent=self.root)
            return
        if confirm and not messagebox.askyesno(
            "Close Session",
            f"Close session {self._session.session_id}?",
            parent=self.root
        ):
            return

        db.log_action(self._session.session_id, "SESSION_CLOSED")
        self._session.close()
        self._session = None
        self._refresh_session_display()
        self._clear_panels()
        self._status_bar.set_status("Session closed", "idle")

    # ── Panel refresh ─────────────────────────────────────────────────────────

    def _on_session_update(self, session: InvestigationSession) -> None:
        """Called by session.notify_subscribers() — always on main thread."""
        self._card_packets.set_value(f"{session.packet_count:,}")
        self._card_flows.set_value(f"{session.flow_count:,}")
        self._card_payload.set_value(format_bytes(session.payload_bytes))
        self._card_findings.set_value(str(session.finding_count))

    def update_stats(self, packets: int, flows: int,
                     payload_bytes: int, findings: int) -> None:
        """Public API for child windows to push stats updates."""
        self._card_packets.set_value(f"{packets:,}")
        self._card_flows.set_value(f"{flows:,}")
        self._card_payload.set_value(format_bytes(payload_bytes))
        self._card_findings.set_value(str(findings))
        if self._session:
            self._session.set_finding_count(findings)

    def _refresh_session_display(self) -> None:
        if self._session:
            self._sess_id_lbl.configure(
                text=f"Session: {self._session.session_id}")
            self._sess_src_lbl.configure(
                text=f"Source: {self._session.source_label}")
            self._sess_status_lbl.configure(
                text=self._session.status,
                fg=FG_SUCCESS if self._session.status == SessionStatus.CAPTURING
                   else FG_SECONDARY)
        else:
            self._sess_id_lbl.configure(text="Session: —")
            self._sess_src_lbl.configure(text="Source: —")
            self._sess_dur_lbl.configure(text="Duration: —")
            self._sess_status_lbl.configure(
                text="NO ACTIVE SESSION", fg=FG_MUTED)
            for card in (self._card_packets, self._card_flows,
                         self._card_payload, self._card_findings):
                card.set_value("—")

    def _refresh_findings_panel(self) -> None:
        if not self._session:
            return
        findings = db.get_findings(self._session.session_id)
        if not findings:
            self._findings_tree.delete(*self._findings_tree.get_children())
            self._show_empty(self._findings_tree, self._findings_empty)
            for v in self._sev_labels.values():
                v.configure(text="0")
            return

        self._findings_empty.pack_forget()
        self._findings_tree.delete(*self._findings_tree.get_children())

        sev_counts = {s: 0 for s in SEVERITY_COLORS}
        for f in findings:
            sev = f.get("severity", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        for sev, count in sev_counts.items():
            self._sev_labels[sev].configure(
                text=str(count),
                fg=SEVERITY_COLORS.get(sev, FG_SECONDARY) if count > 0
                   else FG_MUTED)

        for f in findings[:20]:
            sev = f.get("severity", "INFO")
            self._findings_tree.insert("", "end", values=(
                sev,
                f.get("title", "")[:45],
                f.get("state", "NEW"),
            ), tags=(sev,))

    def _refresh_timeline_panel(self) -> None:
        if not self._session:
            return

        # Load recent timeline events from DB
        conn = db.get_connection()
        rows = conn.execute(
            """SELECT event_time, event_type, description
               FROM timeline_events
               WHERE session_id=?
               ORDER BY event_time DESC LIMIT 30""",
            (self._session.session_id,)
        ).fetchall()
        conn.close()

        if not rows:
            self._show_empty(self._timeline_tree, self._timeline_empty)
            return

        self._timeline_empty.pack_forget()
        self._timeline_tree.delete(*self._timeline_tree.get_children())

        for i, row in enumerate(reversed(rows)):
            etype = row["event_type"] or "GENERAL"
            tag   = etype if etype in ("DNS","TCP","TLS","UDP","ACTION") \
                    else ("even" if i % 2 == 0 else "odd")
            self._timeline_tree.insert("", "end", values=(
                (row["event_time"] or "")[-8:],
                etype,
                (row["description"] or "")[:60],
            ), tags=(tag,))

    def _clear_panels(self) -> None:
        for tree in (self._findings_tree, self._timeline_tree):
            tree.delete(*tree.get_children())
        for v in self._sev_labels.values():
            v.configure(text="—")

    def _show_empty(self, tree: ttk.Treeview, label: tk.Label) -> None:
        tree.delete(*tree.get_children())
        label.place(relx=0.5, rely=0.5, anchor="center")

    # ── Clock ─────────────────────────────────────────────────────────────────

    def _tick(self) -> None:
        if self._session and self._session.capture_start:
            self._sess_dur_lbl.configure(
                text=f"Duration: {self._session.duration}")
        self.root.after(1000, self._tick)

    # ── Module launchers ──────────────────────────────────────────────────────

    def _require_session(self, name: str) -> bool:
        if not self._session:
            messagebox.showwarning(
                "No Session",
                f"Create or open a session before opening {name}.",
                parent=self.root)
            return False
        return True

    def _get_live_data(self) -> tuple[list, list]:
        """Return (packets, flows) — live if capture window open, else DB."""
        if (self._capture_window
                and self._capture_window.window.winfo_exists()):
            return (self._capture_window._packets,
                    self._capture_window._flow_tracker.get_all_flows())
        packets = db.get_packets(self._session.session_id)
        flows   = db.get_flows(self._session.session_id)
        return packets, flows

    def _open_capture(self) -> None:
        if not self._require_session("Payload Capture"):
            return
        if self._capture_window and self._capture_window.window.winfo_exists():
            self._capture_window.window.lift()
            return
        from ui.capture_window import CaptureWindow
        self._capture_window = CaptureWindow(
            self.root,
            session_id=self._session.session_id,
            on_stats_update=self.update_stats,
        )
        self._session.start_capture()
        self._refresh_session_display()

    def _open_flows(self) -> None:
        if not self._require_session("Flow Investigation"):
            return
        packets, flows = self._get_live_data()
        from ui.flow_window import FlowWindow
        FlowWindow(self.root, self._session.session_id, packets, flows)

    def _open_dns(self) -> None:
        if not self._require_session("DNS Analysis"):
            return
        packets, _ = self._get_live_data()
        from ui.dns_window import DnsWindow
        DnsWindow(self.root, self._session.session_id, packets)

    def _open_alerts(self) -> None:
        if not self._require_session("Alerts & Findings"):
            return
        packets, flows = self._get_live_data()
        from ui.alerts_window import AlertsWindow
        w = AlertsWindow(self.root, self._session.session_id, packets, flows)
        # Refresh findings panel when alerts window closes
        self.root.after(500, self._refresh_findings_panel)

    def _open_timeline(self) -> None:
        if not self._require_session("Timeline"):
            return
        packets, _ = self._get_live_data()
        from ui.timeline_window import TimelineWindow
        TimelineWindow(self.root, self._session.session_id, packets)

    def _open_ip(self) -> None:
        if not self._require_session("IP Investigation"):
            return
        packets, flows = self._get_live_data()
        from ui.ip_window import IPWindow
        IPWindow(self.root, self._session.session_id, packets, flows)

    def _open_reports(self) -> None:
        if not self._require_session("Report Center"):
            return
        packets, flows = self._get_live_data()
        from ui.report_window import ReportWindow
        ReportWindow(self.root, self._session.session_id, packets, flows)

    def _open_search(self) -> None:
        if not self._require_session("Global Search"):
            return
        from ui.search_window import SearchWindow
        SearchWindow(self.root, self._session.session_id)

    def _open_audit(self) -> None:
        if not self._require_session("Audit Trail"):
            return
        from ui.audit_window import AuditWindow
        AuditWindow(self.root, self._session.session_id)

    def _open_settings(self) -> None:
        from ui.settings_window import SettingsWindow
        SettingsWindow(self.root)

    def _on_close(self) -> None:
        """
        Safe shutdown — stop any running capture, close the session,
        then destroy the window.

        Called when the user clicks the window's close button.  Replaces
        the bare ``root.destroy`` that main.py would otherwise use, so a
        capture thread or an open child window never gets orphaned.
        """
        log.info("MainWindow safe-shutdown initiated")

        # Stop a live capture if one is running
        if (self._capture_window
                and self._capture_window.window.winfo_exists()):
            try:
                self._capture_window._engine.stop()
            except Exception as exc:
                log.warning("Error stopping capture on shutdown: %s", exc)

        # Close the active session (saves state to the database)
        if self._session:
            try:
                db.log_action(self._session.session_id, "SESSION_CLOSED")
                self._session.close()
            except Exception as exc:
                log.warning("Error closing session on shutdown: %s", exc)

        # Persist settings
        try:
            import config.settings as settings
            settings.save()
        except Exception as exc:
            log.warning("Error saving settings on shutdown: %s", exc)

        self.root.destroy()

    def _open_about(self) -> None:
        """Owner details, social profiles and the bundled legal documents."""
        from ui.about_window import AboutWindow
        AboutWindow(self.root)


# ─── Session Picker Dialog ────────────────────────────────────────────────────

class _SessionPickerDialog:
    def __init__(self, parent, sessions: list[dict], on_select):
        win = tk.Toplevel(parent)
        win.title("Open Session")
        win.geometry("560x360")
        win.configure(bg=BG_DARK)
        win.grab_set()

        tk.Label(win, text="Select a session to open:",
                 bg=BG_DARK, fg=FG_PRIMARY, font=FONT_BODY,
                 anchor="w").pack(fill="x", padx=PAD_OUTER,
                                  pady=(PAD_OUTER, PAD_SMALL))

        frame = tk.Frame(win, bg=BG_DARK)
        frame.pack(fill="both", expand=True, padx=PAD_OUTER)

        cols = ("SESSION ID", "DATE", "PACKETS", "STATUS")
        tree = ttk.Treeview(frame, columns=cols,
                             show="headings", selectmode="browse")
        for col in cols:
            tree.heading(col, text=col)
        tree.column("SESSION ID", width=160)
        tree.column("DATE",       width=90)
        tree.column("PACKETS",    width=80)
        tree.column("STATUS",     width=80)

        for s in sessions:
            status = "OPEN" if not s.get("closed_at") else "CLOSED"
            tree.insert("", "end", iid=s["session_id"], values=(
                s["session_id"],
                (s.get("created_at") or "")[:10],
                f"{s.get('total_packets', 0):,}",
                status,
            ))

        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)

        btn_row = tk.Frame(win, bg=BG_DARK)
        btn_row.pack(fill="x", padx=PAD_OUTER, pady=PAD_INNER)

        def open_selected():
            sel = tree.selection()
            if sel:
                on_select(sel[0])
                win.destroy()

        DarkButton(btn_row, "OPEN", command=open_selected,
                   accent=True).pack(side="left")
        DarkButton(btn_row, "CANCEL",
                   command=win.destroy).pack(side="left", padx=PAD_SMALL)
        tree.bind("<Double-1>", lambda e: open_selected())
