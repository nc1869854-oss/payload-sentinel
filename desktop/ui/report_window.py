"""
ui/report_window.py

Report Center — Evidence & Audit workstation.

This window separates cleanly from live capture. It works with
completed or in-progress sessions, pulls data from the database
(and live memory if available), and generates professional reports.

Workflow:
  1. Analyst selects a session from the left panel
  2. Session summary is displayed
  3. Analyst selects which sections to include
  4. Analyst enters their name and any final notes
  5. Click GENERATE HTML / GENERATE PDF / EXPORT CSV / EXPORT JSON
  6. File is written, hashed, recorded in evidence_files table
  7. Hash is displayed for chain-of-custody documentation
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pathlib
import datetime
import threading

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT, FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS,
    FG_MUTED,
    FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL, PAD_TINY,
    REPORT_WINDOW_SIZE,
)
from ui.widgets import (
    DarkButton, StatusBar, horizontal_separator,
    section_header, detail_row,
)
from evidence.database import (
    get_all_sessions, get_session, get_connection,
)
from evidence.sessions import format_bytes
from evidence.hashing import record_evidence_file, format_hash_display
from reports.report_builder import build_report_data, ALL_SECTIONS
from reports.html_report import generate_html_report
from reports.csv_report import generate_csv_export
from reports.json_report import generate_json_export
import config.settings as settings


class ReportWindow:
    """
    Report Center workstation.

    Parameters
    ----------
    parent     : Tk root window
    session_id : currently active session (pre-selects it in the list)
    packets    : live in-memory packets (optional — falls back to DB)
    flows      : live in-memory flows (optional)
    """

    def __init__(self, parent: tk.Tk, session_id: str = "",
                 packets: list = None, flows: list = None):
        self.parent         = parent
        self._active_sid    = session_id
        self._live_packets  = packets or []
        self._live_flows    = flows   or []
        self._selected_sid  = session_id   # session currently shown in right panel

        self.window = tk.Toplevel(parent)
        self.window.title("Report Center — Evidence & Audit")
        self.window.geometry(REPORT_WINDOW_SIZE)
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self.window.destroy)

        self._build_ui()
        self._load_sessions()

        if session_id:
            self._select_session(session_id)

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        horizontal_separator(self.window).pack(fill="x")

        body = tk.Frame(self.window, bg=BG_DARK)
        body.pack(fill="both", expand=True)

        self._build_session_list(body)
        self._build_report_panel(body)

        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

    def _build_header(self) -> None:
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        left = tk.Frame(header, bg=BG_CARD)
        left.pack(side="left")

        tk.Label(left, text="REPORT CENTER", bg=BG_CARD,
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(left, text="Evidence preservation · Investigation reports · Audit trail",
                 bg=BG_CARD, fg=FG_SECONDARY, font=FONT_SMALL).pack(anchor="w")

        right = tk.Frame(header, bg=BG_CARD)
        right.pack(side="right")
        DarkButton(right, "REFRESH SESSIONS",
                   command=self._load_sessions).pack(side="right")

    def _build_session_list(self, parent: tk.Frame) -> None:
        """Left panel — list of all investigation sessions."""
        frame = tk.Frame(parent, bg=BG_DARK, width=230)
        frame.pack(side="left", fill="y")
        frame.pack_propagate(False)

        section_header(frame, "SESSIONS").pack(
            fill="x", padx=PAD_INNER, pady=(PAD_INNER, PAD_TINY)
        )

        list_frame = tk.Frame(frame, bg=BG_DARK)
        list_frame.pack(fill="both", expand=True, padx=PAD_TINY)

        cols = ("ID", "DATE", "PKTS")
        self._session_tree = ttk.Treeview(
            list_frame, columns=cols, show="headings", selectmode="browse"
        )
        self._session_tree.heading("ID",   text="SESSION ID")
        self._session_tree.heading("DATE", text="DATE")
        self._session_tree.heading("PKTS", text="PKTS")
        self._session_tree.column("ID",   width=120, anchor="w")
        self._session_tree.column("DATE", width=80,  anchor="w")
        self._session_tree.column("PKTS", width=60,  anchor="e")

        self._session_tree.tag_configure("active", foreground=FG_SUCCESS)
        self._session_tree.tag_configure("closed", foreground=FG_SECONDARY)

        scroll = ttk.Scrollbar(list_frame, orient="vertical",
                               command=self._session_tree.yview)
        self._session_tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self._session_tree.pack(fill="both", expand=True)

        self._session_tree.bind("<<TreeviewSelect>>", self._on_session_selected)

        # Delete session button (at bottom of list)
        horizontal_separator(frame).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)
        DarkButton(frame, "DELETE SESSION",
                   command=self._delete_session, danger=True
                   ).pack(fill="x", padx=PAD_INNER, pady=PAD_TINY)

    def _build_report_panel(self, parent: tk.Frame) -> None:
        """Right panel — session summary, section checkboxes, export buttons."""
        panel = tk.Frame(parent, bg=BG_DARK)
        panel.pack(side="right", fill="both", expand=True)

        # Scrollable inner frame
        canvas = tk.Canvas(panel, bg=BG_DARK, highlightthickness=0)
        scroll = ttk.Scrollbar(panel, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG_DARK)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(win_id, width=e.width))
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        p = inner

        # ── Session summary ───────────────────────────────────────────────────
        sum_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        sum_frame.pack(fill="x", padx=PAD_INNER, pady=(PAD_INNER, PAD_SMALL))

        section_header(sum_frame, "SESSION SUMMARY", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        self._sum_labels: dict[str, tk.Label] = {}

        two_col = tk.Frame(sum_frame, bg=BG_CARD)
        two_col.pack(fill="x")
        left  = tk.Frame(two_col, bg=BG_CARD)
        right = tk.Frame(two_col, bg=BG_CARD)
        left.pack(side="left", fill="both", expand=True)
        right.pack(side="left", fill="both", expand=True)

        left_fields = [
            ("session_id",  "Session ID"),
            ("created_at",  "Captured"),
            ("duration",    "Duration"),
            ("interface",   "Interface"),
            ("mode",        "Mode"),
        ]
        right_fields = [
            ("packets",  "Packets"),
            ("flows",    "Flows"),
            ("bytes",    "Bytes"),
            ("findings", "Findings"),
            ("alerts",   "Alerts"),
        ]

        for key, label in left_fields:
            _, v = detail_row(left, label, "—", bg=BG_CARD)
            self._sum_labels[key] = v

        for key, label in right_fields:
            _, v = detail_row(right, label, "—", bg=BG_CARD)
            self._sum_labels[key] = v

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Analyst info ──────────────────────────────────────────────────────
        analyst_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        analyst_frame.pack(fill="x", padx=PAD_INNER, pady=(0, PAD_SMALL))

        section_header(analyst_frame, "REPORT DETAILS", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        name_row = tk.Frame(analyst_frame, bg=BG_CARD)
        name_row.pack(fill="x")
        tk.Label(name_row, text="Analyst Name:", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_LABEL, width=16,
                 anchor="w").pack(side="left")
        self._analyst_var = tk.StringVar(value="Analyst")
        ttk.Entry(name_row, textvariable=self._analyst_var,
                  width=30).pack(side="left", padx=PAD_SMALL)

        dir_row = tk.Frame(analyst_frame, bg=BG_CARD)
        dir_row.pack(fill="x", pady=(PAD_SMALL, 0))
        tk.Label(dir_row, text="Export Directory:", bg=BG_CARD,
                 fg=FG_SECONDARY, font=FONT_LABEL, width=16,
                 anchor="w").pack(side="left")
        self._export_dir_var = tk.StringVar(
            value=settings.get("export_directory",
                               str(pathlib.Path.home() / "PayloadCaptureExports"))
        )
        ttk.Entry(dir_row, textvariable=self._export_dir_var,
                  width=28).pack(side="left", padx=PAD_SMALL)
        DarkButton(dir_row, "BROWSE",
                   command=self._browse_dir).pack(side="left")

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Section checkboxes ────────────────────────────────────────────────
        chk_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        chk_frame.pack(fill="x", padx=PAD_INNER, pady=(0, PAD_SMALL))

        section_header(chk_frame, "REPORT SECTIONS", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        self._section_vars: dict[str, tk.BooleanVar] = {}

        # Two-column checkbox layout
        cols_frame = tk.Frame(chk_frame, bg=BG_CARD)
        cols_frame.pack(fill="x")

        items = list(ALL_SECTIONS.items())
        mid   = (len(items) + 1) // 2
        left_items  = items[:mid]
        right_items = items[mid:]

        for col_items, side in [(left_items, "left"), (right_items, "right")]:
            col = tk.Frame(cols_frame, bg=BG_CARD)
            col.pack(side=side, fill="both", expand=True)
            for key, label in col_items:
                var = tk.BooleanVar(value=True)
                self._section_vars[key] = var
                tk.Checkbutton(
                    col, text=label, variable=var,
                    bg=BG_CARD, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                    activebackground=BG_CARD, activeforeground=FG_PRIMARY,
                    font=FONT_SMALL,
                ).pack(anchor="w")

        # Select/deselect all
        btn_row = tk.Frame(chk_frame, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(PAD_SMALL, 0))
        DarkButton(btn_row, "SELECT ALL",
                   command=self._select_all_sections).pack(side="left", padx=2)
        DarkButton(btn_row, "DESELECT ALL",
                   command=self._deselect_all_sections).pack(side="left", padx=2)

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Generate buttons ──────────────────────────────────────────────────
        gen_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        gen_frame.pack(fill="x", padx=PAD_INNER, pady=(0, PAD_SMALL))

        section_header(gen_frame, "GENERATE REPORT", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        btn_row1 = tk.Frame(gen_frame, bg=BG_CARD)
        btn_row1.pack(fill="x")

        DarkButton(btn_row1, "GENERATE HTML",
                   command=self._generate_html, accent=True
                   ).pack(side="left", padx=(0, PAD_SMALL))
        DarkButton(btn_row1, "GENERATE PDF",
                   command=self._generate_pdf, accent=True
                   ).pack(side="left", padx=(0, PAD_SMALL))
        DarkButton(btn_row1, "EXPORT CSV",
                   command=self._export_csv
                   ).pack(side="left", padx=(0, PAD_SMALL))
        DarkButton(btn_row1, "EXPORT JSON",
                   command=self._export_json
                   ).pack(side="left")

        horizontal_separator(p).pack(fill="x", padx=PAD_INNER, pady=PAD_SMALL)

        # ── Evidence files & hashes ───────────────────────────────────────────
        ev_frame = tk.Frame(p, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        ev_frame.pack(fill="x", padx=PAD_INNER, pady=(0, PAD_INNER))

        section_header(ev_frame, "EVIDENCE FILES & HASHES", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        self._evidence_frame = tk.Frame(ev_frame, bg=BG_CARD)
        self._evidence_frame.pack(fill="x")

        tk.Label(self._evidence_frame,
                 text="(generate a report to create evidence records)",
                 bg=BG_CARD, fg=FG_MUTED, font=FONT_SMALL).pack(anchor="w")

    # ── Session Management ────────────────────────────────────────────────────

    def _load_sessions(self) -> None:
        """Populate the session list from the database."""
        self._session_tree.delete(*self._session_tree.get_children())
        sessions = get_all_sessions()

        for s in sessions:
            sid    = s["session_id"]
            is_active = sid == self._active_sid
            tag    = "active" if is_active else "closed"
            date   = (s.get("created_at") or "")[:10]
            pkts   = f"{s.get('total_packets', 0):,}"

            self._session_tree.insert(
                "", "end", iid=sid,
                values=(sid, date, pkts),
                tags=(tag,),
            )

        # Auto-select the active session
        if self._active_sid and self._active_sid in \
                self._session_tree.get_children():
            self._session_tree.selection_set(self._active_sid)
            self._session_tree.see(self._active_sid)

        self._status_bar.set_status(f"{len(sessions)} sessions loaded", "idle")

    def _on_session_selected(self, event) -> None:
        sel = self._session_tree.selection()
        if sel:
            self._select_session(sel[0])

    def _select_session(self, session_id: str) -> None:
        self._selected_sid = session_id
        self._refresh_summary(session_id)
        self._refresh_evidence_list(session_id)

    def _refresh_summary(self, session_id: str) -> None:
        """Fill the session summary panel."""
        s = get_session(session_id)
        if not s:
            return

        from evidence.sessions import format_duration
        import datetime

        created = s.get("created_at", "")
        closed  = s.get("closed_at", "")
        try:
            start = datetime.datetime.fromisoformat(created)
            end   = (datetime.datetime.fromisoformat(closed)
                     if closed else datetime.datetime.now())
            dur   = format_duration(start, end)
        except Exception:
            dur = "—"

        self._sum_labels["session_id"].configure(text=session_id)
        self._sum_labels["created_at"].configure(text=created[:19])
        self._sum_labels["duration"].configure(text=dur)
        self._sum_labels["interface"].configure(
            text=s.get("interface") or "—")
        self._sum_labels["mode"].configure(
            text=s.get("capture_mode", "LIVE"))
        self._sum_labels["packets"].configure(
            text=f"{s.get('total_packets', 0):,}")
        self._sum_labels["flows"].configure(
            text=f"{s.get('total_flows', 0):,}")
        self._sum_labels["bytes"].configure(
            text=format_bytes(s.get("total_bytes", 0) or 0))
        self._sum_labels["findings"].configure(
            text=str(s.get("total_alerts", 0) or 0))
        self._sum_labels["alerts"].configure(
            text=str(s.get("total_alerts", 0) or 0))

    def _refresh_evidence_list(self, session_id: str) -> None:
        """Show existing evidence files for this session."""
        for w in self._evidence_frame.winfo_children():
            w.destroy()

        conn  = get_connection()
        rows  = conn.execute(
            "SELECT * FROM evidence_files WHERE session_id = ? ORDER BY created_at DESC",
            (session_id,)
        ).fetchall()
        conn.close()

        if not rows:
            tk.Label(self._evidence_frame,
                     text="(no evidence files for this session yet)",
                     bg=BG_CARD, fg=FG_MUTED, font=FONT_SMALL).pack(anchor="w")
            return

        for row in rows:
            card = tk.Frame(self._evidence_frame, bg=BG_INPUT,
                            padx=PAD_SMALL, pady=PAD_SMALL)
            card.pack(fill="x", pady=2)

            tk.Label(card, text=row["filename"], bg=BG_INPUT,
                     fg=FG_PRIMARY, font=FONT_LABEL, anchor="w").pack(anchor="w")
            tk.Label(card, text=f"Type: {row['file_type']}  |  {row['created_at'][:19]}",
                     bg=BG_INPUT, fg=FG_SECONDARY, font=FONT_SMALL, anchor="w"
                     ).pack(anchor="w")

            hash_display = format_hash_display(row["sha256"] or "")
            tk.Label(card, text=f"SHA-256: {hash_display}",
                     bg=BG_INPUT, fg=FG_SUCCESS, font=FONT_MONO,
                     anchor="w", wraplength=580
                     ).pack(anchor="w")

            def make_verify(fp, h):
                def verify():
                    from evidence.hashing import verify_file
                    ok = verify_file(fp, h)
                    if ok:
                        messagebox.showinfo("Verified",
                            f"✓ Hash matches — file is unaltered.\n{fp}",
                            parent=self.window)
                    else:
                        messagebox.showwarning("Mismatch",
                            f"⚠ Hash does NOT match — file may have been modified.\n{fp}",
                            parent=self.window)
                return verify

            DarkButton(card, "VERIFY HASH",
                       command=make_verify(row["file_path"], row["sha256"])
                       ).pack(anchor="w", pady=(4, 0))

    def _delete_session(self) -> None:
        """Permanently delete the selected session after confirmation."""
        if not self._selected_sid:
            return

        answer = messagebox.askyesno(
            "Delete Session",
            f"Permanently delete session {self._selected_sid}?\n\n"
            "This removes all packets, flows, alerts, findings, notes,\n"
            "and evidence records. This cannot be undone.",
            icon="warning", parent=self.window
        )
        if not answer:
            return

        # Second confirmation for destructive action
        answer2 = messagebox.askyesno(
            "Confirm Deletion",
            "Are you absolutely sure? All data will be lost.",
            icon="warning", parent=self.window
        )
        if not answer2:
            return

        from evidence.database import delete_session
        delete_session(self._selected_sid)
        self._selected_sid = ""
        self._load_sessions()
        self._status_bar.set_status("Session deleted", "idle")

    # ── Report Generation ─────────────────────────────────────────────────────

    def _get_sections(self) -> dict:
        """Return the currently selected sections dict."""
        return {key: var.get() for key, var in self._section_vars.items()}

    def _get_output_path(self, extension: str) -> pathlib.Path | None:
        """Build the default output path and ensure the directory exists."""
        if not self._selected_sid:
            messagebox.showwarning("No Session",
                                   "Select a session first.", parent=self.window)
            return None

        export_dir = pathlib.Path(self._export_dir_var.get())
        export_dir.mkdir(parents=True, exist_ok=True)

        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{self._selected_sid}_{ts}{extension}"
        return export_dir / filename

    def _get_report_data(self) -> dict | None:
        """Build report data for the selected session."""
        if not self._selected_sid:
            messagebox.showwarning("No Session",
                                   "Select a session first.", parent=self.window)
            return None

        # Use live data if this is the active session
        packets = self._live_packets if self._selected_sid == self._active_sid else None
        flows   = self._live_flows   if self._selected_sid == self._active_sid else None

        try:
            return build_report_data(
                session_id=self._selected_sid,
                sections=self._get_sections(),
                analyst_name=self._analyst_var.get().strip() or "Analyst",
                packets=packets,
                flows=flows,
            )
        except Exception as e:
            messagebox.showerror("Data Error", str(e), parent=self.window)
            return None

    def _generate_html(self) -> None:
        path = self._get_output_path(".html")
        if not path:
            return

        self._status_bar.set_status("Generating HTML report…", "active")
        self.window.update_idletasks()

        def run():
            try:
                data = self._get_report_data()
                if not data:
                    return
                out = generate_html_report(data, path)
                record_evidence_file(self._selected_sid, out, "HTML_REPORT")
                self.window.after(0, lambda: self._on_report_done(out))
            except Exception as exc:
                msg = str(exc)
                self.window.after(0, lambda m=msg: self._on_report_error(m))

        threading.Thread(target=run, daemon=True).start()

    def _generate_pdf(self) -> None:
        from reports.pdf_report import REPORTLAB_AVAILABLE
        if not REPORTLAB_AVAILABLE:
            messagebox.showerror(
                "ReportLab Required",
                "PDF generation requires reportlab.\n\n"
                "Install it with:\n    pip install reportlab",
                parent=self.window
            )
            return

        path = self._get_output_path(".pdf")
        if not path:
            return

        self._status_bar.set_status("Generating PDF report…", "active")
        self.window.update_idletasks()

        def run():
            try:
                from reports.pdf_report import generate_pdf_report
                data = self._get_report_data()
                if not data:
                    return
                out = generate_pdf_report(data, path)
                record_evidence_file(self._selected_sid, out, "PDF_REPORT")
                self.window.after(0, lambda: self._on_report_done(out))
            except Exception as exc:
                msg = str(exc)
                self.window.after(0, lambda m=msg: self._on_report_error(m))

        threading.Thread(target=run, daemon=True).start()

    def _export_csv(self) -> None:
        path = self._get_output_path(".zip")
        if not path:
            return

        self._status_bar.set_status("Exporting CSV…", "active")

        def run():
            try:
                data = self._get_report_data()
                if not data:
                    return
                out = generate_csv_export(data, path)
                record_evidence_file(self._selected_sid, out, "CSV_EXPORT")
                self.window.after(0, lambda: self._on_report_done(out))
            except Exception as exc:
                msg = str(exc)
                self.window.after(0, lambda m=msg: self._on_report_error(m))

        threading.Thread(target=run, daemon=True).start()

    def _export_json(self) -> None:
        path = self._get_output_path(".json")
        if not path:
            return

        self._status_bar.set_status("Exporting JSON…", "active")

        def run():
            try:
                data = self._get_report_data()
                if not data:
                    return
                out = generate_json_export(data, path)
                record_evidence_file(self._selected_sid, out, "JSON_EXPORT")
                self.window.after(0, lambda: self._on_report_done(out))
            except Exception as exc:
                msg = str(exc)
                self.window.after(0, lambda m=msg: self._on_report_error(m))

        threading.Thread(target=run, daemon=True).start()

    def _on_report_done(self, output_path: str) -> None:
        """Called on the main thread when a report finishes."""
        self._refresh_evidence_list(self._selected_sid)
        self._status_bar.set_status(f"Report written: {output_path}", "idle")

        answer = messagebox.askyesno(
            "Report Generated",
            f"Report saved to:\n{output_path}\n\nOpen the containing folder?",
            parent=self.window
        )
        if answer:
            self._open_folder(pathlib.Path(output_path).parent)

    def _on_report_error(self, error: str) -> None:
        """Called on the main thread when report generation fails."""
        self._status_bar.set_status("Report generation failed", "error")
        messagebox.showerror("Report Error",
                             f"Could not generate report:\n\n{error}",
                             parent=self.window)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _browse_dir(self) -> None:
        chosen = filedialog.askdirectory(
            title="Select Export Directory",
            initialdir=self._export_dir_var.get(),
            parent=self.window,
        )
        if chosen:
            self._export_dir_var.set(chosen)

    def _select_all_sections(self) -> None:
        for var in self._section_vars.values():
            var.set(True)

    def _deselect_all_sections(self) -> None:
        for var in self._section_vars.values():
            var.set(False)

    def _open_folder(self, path: pathlib.Path) -> None:
        """Open a folder in the OS file manager."""
        import subprocess, sys
        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", str(path)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception:
            pass
