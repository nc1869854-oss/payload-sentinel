"""
ui/pcap_window.py

PCAP Import / Export window.

Import:
  - Browse for a .pcap or .pcapng file
  - Preview packet count and time range before committing
  - Import feeds packets through the same pipeline as live capture
  - Session is tagged PCAP ANALYSIS so the analyst always knows
    they are working with a file, not live traffic

Export:
  - Write the current session's raw packets to a .pcap file
  - The file can then be opened in Wireshark or shared
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue
import pathlib
import threading
import datetime

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT, BG_SELECTED,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS,
    FG_WARNING, FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
)
from ui.widgets import DarkButton, StatusBar, horizontal_separator, section_header
from capture.pcap import (
    import_pcap_threaded, get_pcap_info,
    SCAPY_AVAILABLE,
)
from evidence.sessions import format_bytes


class PcapWindow:
    """
    PCAP Import / Export workstation.

    Parameters
    ----------
    parent          : Tk root window
    session_id      : active session ID
    packet_queue    : the capture window's queue (imports feed into it)
    raw_packets     : list of raw Scapy packets (for export)
    on_import_start : callback() — called when import begins so the
                      capture window can switch to PCAP ANALYSIS mode
    """

    def __init__(self, parent: tk.Tk, session_id: str,
                 packet_queue: queue.Queue,
                 raw_packets: list,
                 on_import_start=None):
        self.parent         = parent
        self.session_id     = session_id
        self._queue         = packet_queue
        self._raw_packets   = raw_packets
        self._on_import_start = on_import_start
        self._importer      = None   # active PcapImporter (for cancel)

        self.window = tk.Toplevel(parent)
        self.window.title("PCAP Import / Export")
        self.window.geometry("680x540")
        self.window.configure(bg=BG_DARK)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_ui()

        if not SCAPY_AVAILABLE:
            self._status_bar.set_status(
                "Scapy not installed — PCAP import/export unavailable", "error")

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        tk.Label(header, text="PCAP IMPORT / EXPORT", bg=BG_CARD,
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(side="left")

        horizontal_separator(self.window).pack(fill="x")

        body = tk.Frame(self.window, bg=BG_DARK, padx=PAD_OUTER, pady=PAD_INNER)
        body.pack(fill="both", expand=True)

        self._build_import_section(body)

        horizontal_separator(body).pack(fill="x", pady=PAD_INNER)

        self._build_export_section(body)

        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

    def _build_import_section(self, parent: tk.Frame) -> None:
        section_header(parent, "IMPORT PCAP FILE").pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        tk.Label(parent,
                 text="Import an existing .pcap or .pcapng capture file. "
                      "Packets are fed through the same analysis pipeline as live traffic.",
                 bg=BG_DARK, fg=FG_SECONDARY, font=FONT_SMALL,
                 wraplength=600, justify="left").pack(anchor="w")

        tk.Frame(parent, bg=BG_DARK, height=PAD_SMALL).pack()

        # File picker row
        pick_row = tk.Frame(parent, bg=BG_DARK)
        pick_row.pack(fill="x")

        tk.Label(pick_row, text="File:", bg=BG_DARK, fg=FG_SECONDARY,
                 font=FONT_LABEL, width=8, anchor="w").pack(side="left")

        self._file_var = tk.StringVar()
        file_entry = ttk.Entry(pick_row, textvariable=self._file_var, width=52)
        file_entry.pack(side="left", padx=PAD_SMALL)

        DarkButton(pick_row, "BROWSE",
                   command=self._browse_pcap).pack(side="left")

        tk.Frame(parent, bg=BG_DARK, height=PAD_SMALL).pack()

        # File info preview
        info_frame = tk.Frame(parent, bg=BG_CARD, padx=PAD_INNER, pady=PAD_SMALL)
        info_frame.pack(fill="x")

        section_header(info_frame, "FILE PREVIEW", bg=BG_CARD).pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        self._info_labels: dict[str, tk.Label] = {}
        for key, label in [
            ("packet_count", "Packets"),
            ("file_size",    "File Size"),
            ("first_time",   "First Packet"),
            ("last_time",    "Last Packet"),
        ]:
            row = tk.Frame(info_frame, bg=BG_CARD)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=label, bg=BG_CARD, fg=FG_SECONDARY,
                     font=FONT_SMALL, width=16, anchor="w").pack(side="left")
            val = tk.Label(row, text="—", bg=BG_CARD, fg=FG_PRIMARY,
                           font=FONT_MONO, anchor="w")
            val.pack(side="left")
            self._info_labels[key] = val

        tk.Frame(parent, bg=BG_DARK, height=PAD_SMALL).pack()

        # Progress bar
        self._progress_var = tk.DoubleVar(value=0)
        self._progress_bar = ttk.Progressbar(
            parent, variable=self._progress_var,
            maximum=100, mode="determinate"
        )
        self._progress_bar.pack(fill="x")

        self._progress_label = tk.Label(
            parent, text="", bg=BG_DARK, fg=FG_SECONDARY, font=FONT_SMALL
        )
        self._progress_label.pack(anchor="w")

        tk.Frame(parent, bg=BG_DARK, height=PAD_SMALL).pack()

        # Import buttons
        btn_row = tk.Frame(parent, bg=BG_DARK)
        btn_row.pack(fill="x")

        DarkButton(btn_row, "PREVIEW FILE",
                   command=self._preview_file).pack(side="left", padx=(0, PAD_SMALL))
        DarkButton(btn_row, "START IMPORT",
                   command=self._start_import, accent=True).pack(side="left",
                                                                   padx=(0, PAD_SMALL))
        self._cancel_btn = DarkButton(btn_row, "CANCEL IMPORT",
                                       command=self._cancel_import)
        self._cancel_btn.pack(side="left")
        self._cancel_btn.configure(state="disabled")

    def _build_export_section(self, parent: tk.Frame) -> None:
        section_header(parent, "EXPORT TO PCAP").pack(
            anchor="w", pady=(0, PAD_SMALL)
        )

        count = len(self._raw_packets)
        tk.Label(parent,
                 text=f"Export the current session's captured packets ({count:,} packets) "
                      "to a .pcap file. The file can be opened in Wireshark.",
                 bg=BG_DARK, fg=FG_SECONDARY, font=FONT_SMALL,
                 wraplength=600, justify="left").pack(anchor="w")

        if count == 0:
            tk.Label(parent,
                     text="(No packets in current session — capture some traffic first.)",
                     bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL).pack(anchor="w",
                                                                       pady=PAD_SMALL)

        tk.Frame(parent, bg=BG_DARK, height=PAD_SMALL).pack()

        # Export path row
        export_row = tk.Frame(parent, bg=BG_DARK)
        export_row.pack(fill="x")

        tk.Label(export_row, text="Save to:", bg=BG_DARK, fg=FG_SECONDARY,
                 font=FONT_LABEL, width=8, anchor="w").pack(side="left")

        self._export_path_var = tk.StringVar(
            value=str(pathlib.Path.home() / "PayloadCaptureExports" /
                      f"session_{self.session_id}.pcap")
        )
        ttk.Entry(export_row, textvariable=self._export_path_var,
                  width=52).pack(side="left", padx=PAD_SMALL)

        DarkButton(export_row, "BROWSE",
                   command=self._browse_export_path).pack(side="left")

        tk.Frame(parent, bg=BG_DARK, height=PAD_SMALL).pack()

        export_note = tk.Label(
            parent,
            text="⚠  Note: Raw packet export requires that the capture "
                 "window stored the original Scapy packet objects. "
                 "Sessions loaded from the database cannot be exported to PCAP.",
            bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL,
            wraplength=600, justify="left"
        )
        export_note.pack(anchor="w")

        tk.Frame(parent, bg=BG_DARK, height=PAD_SMALL).pack()

        DarkButton(parent, "EXPORT PCAP",
                   command=self._export_pcap,
                   accent=True).pack(anchor="w")

    # ── Import Logic ──────────────────────────────────────────────────────────

    def _browse_pcap(self) -> None:
        path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[
                ("PCAP files", "*.pcap *.pcapng *.cap"),
                ("All files",  "*.*"),
            ],
            parent=self.window,
        )
        if path:
            self._file_var.set(path)
            self._preview_file()

    def _preview_file(self) -> None:
        """Load file metadata without importing all packets."""
        path = self._file_var.get().strip()
        if not path:
            messagebox.showwarning("No File", "Select a PCAP file first.",
                                   parent=self.window)
            return

        self._status_bar.set_status("Reading file info…", "active")
        self.window.update_idletasks()

        info = get_pcap_info(path)

        if info["error"]:
            self._status_bar.set_status(f"Error: {info['error']}", "error")
            messagebox.showerror("File Error", info["error"], parent=self.window)
            return

        self._info_labels["packet_count"].configure(
            text=f"{info['packet_count']:,}")
        self._info_labels["file_size"].configure(
            text=format_bytes(info["file_size"]))
        self._info_labels["first_time"].configure(
            text=info["first_time"] or "—")
        self._info_labels["last_time"].configure(
            text=info["last_time"] or "—")

        self._status_bar.set_status(
            f"File preview: {info['packet_count']:,} packets, "
            f"{format_bytes(info['file_size'])}",
            "idle"
        )

    def _start_import(self) -> None:
        """Begin importing packets from the selected file."""
        if not SCAPY_AVAILABLE:
            messagebox.showerror(
                "Scapy Required",
                "Scapy is required for PCAP import.\n"
                "Install with:  pip install scapy",
                parent=self.window
            )
            return

        path = self._file_var.get().strip()
        if not path:
            messagebox.showwarning("No File", "Select a PCAP file first.",
                                   parent=self.window)
            return

        if not pathlib.Path(path).exists():
            messagebox.showerror("File Not Found",
                                 f"Could not find:\n{path}",
                                 parent=self.window)
            return

        # Notify the capture window to switch to PCAP ANALYSIS mode
        if self._on_import_start:
            self._on_import_start(pathlib.Path(path).name)

        self._progress_var.set(0)
        self._progress_label.configure(text="Starting import…")
        self._cancel_btn.configure(state="normal")
        self._status_bar.set_status("Importing…", "active")

        # Get total packet count for progress calculation
        info = get_pcap_info(path)
        total = info.get("packet_count", 1) or 1

        def on_progress(loaded: int, total_: int) -> None:
            pct = min(100.0, 100.0 * loaded / total_)
            # Update UI on the main thread
            if self.window.winfo_exists():
                self.window.after(0, lambda p=pct, n=loaded: self._update_progress(p, n, total_))

        self._importer = import_pcap_threaded(
            path, self._queue, progress_callback=on_progress
        )

        # Poll for completion
        self.window.after(200, lambda: self._poll_import_done(total))

    def _poll_import_done(self, total: int) -> None:
        """Check queue for pcap_done signal."""
        # peek at the queue without blocking
        done = False
        try:
            import queue as Q
            # We can't peek non-destructively, so we watch the progress label
            # The pcap_done message is consumed by the capture window's _poll_queue
            # We detect completion via progress reaching 100%
            if self._progress_var.get() >= 99.9:
                done = True
        except Exception:
            pass

        if not done and self.window.winfo_exists():
            self.window.after(300, lambda: self._poll_import_done(total))
        else:
            self._on_import_complete(total)

    def _update_progress(self, pct: float, loaded: int, total: int) -> None:
        self._progress_var.set(pct)
        self._progress_label.configure(
            text=f"Imported {loaded:,} of {total:,} packets  ({pct:.0f}%)"
        )
        if pct >= 100:
            self._on_import_complete(total)

    def _on_import_complete(self, total: int) -> None:
        self._progress_var.set(100)
        self._progress_label.configure(text=f"Import complete — {total:,} packets")
        self._cancel_btn.configure(state="disabled")
        self._status_bar.set_status(
            f"PCAP import complete: {total:,} packets loaded", "idle"
        )

    def _cancel_import(self) -> None:
        if self._importer:
            self._importer.cancel()
            self._cancel_btn.configure(state="disabled")
            self._status_bar.set_status("Import cancelled", "idle")

    # ── Export Logic ──────────────────────────────────────────────────────────

    def _browse_export_path(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export PCAP As",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            initialfile=f"session_{self.session_id}.pcap",
            parent=self.window,
        )
        if path:
            self._export_path_var.set(path)

    def _export_pcap(self) -> None:
        if not SCAPY_AVAILABLE:
            messagebox.showerror(
                "Scapy Required",
                "Scapy is required for PCAP export.\n"
                "Install with:  pip install scapy",
                parent=self.window
            )
            return

        if not self._raw_packets:
            messagebox.showwarning(
                "No Packets",
                "No raw packets available for export.\n\n"
                "Raw packets are only available in the current capture session. "
                "Sessions loaded from the database cannot be exported to PCAP.",
                parent=self.window
            )
            return

        out_path = self._export_path_var.get().strip()
        if not out_path:
            messagebox.showwarning("No Path", "Enter an output path.",
                                   parent=self.window)
            return

        self._status_bar.set_status("Exporting PCAP…", "active")
        self.window.update_idletasks()

        from capture.pcap import export_pcap
        success, message = export_pcap(self._raw_packets, out_path)

        if success:
            # Record the export in the evidence table
            from evidence.hashing import record_evidence_file
            try:
                record_evidence_file(self.session_id, out_path, "PCAP_EXPORT")
            except Exception:
                pass   # evidence recording failure is non-fatal

            self._status_bar.set_status(
                f"PCAP exported: {len(self._raw_packets):,} packets", "idle"
            )
            messagebox.showinfo(
                "Exported",
                f"PCAP file saved to:\n{message}\n\n"
                f"Packets: {len(self._raw_packets):,}",
                parent=self.window
            )
        else:
            self._status_bar.set_status("Export failed", "error")
            messagebox.showerror("Export Error", message, parent=self.window)

    # ── Close ─────────────────────────────────────────────────────────────────

    def _on_close(self) -> None:
        if self._importer:
            self._importer.cancel()
        self.window.destroy()
