"""
ui/settings_window.py

Settings window for Payload Capture Suite.

Groups settings into logical sections:
  - Capture   : interface defaults, packet limits, buffer sizes
  - Analysis  : which rules and analysis modules are active
  - Reports   : default export directory, report content options
  - Firewall  : enable/disable defensive controls
  - About     : version, how to get help

Changes are applied immediately to the in-memory settings dict
and written to disk when the user clicks SAVE.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pathlib

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT, BG_SELECTED,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL, PAD_TINY,
    SETTINGS_WINDOW_SIZE,
)
from ui.widgets import DarkButton, StatusBar, horizontal_separator, section_header
import config.settings as settings
from capture.engine import get_available_interfaces
from firewall.windows_firewall import IS_WINDOWS, check_admin_privileges


class SettingsWindow:
    """Application settings window."""

    def __init__(self, parent: tk.Tk):
        self.parent = parent

        self.window = tk.Toplevel(parent)
        self.window.title("Settings")
        self.window.geometry(SETTINGS_WINDOW_SIZE)
        self.window.configure(bg=BG_DARK)
        self.window.resizable(False, False)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        # Tk variable mirrors — populated from settings in _load_values()
        self._vars: dict[str, tk.Variable] = {}

        self._build_ui()
        self._load_values()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # Header
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")
        tk.Label(header, text="SETTINGS", bg=BG_CARD, fg=FG_ACCENT,
                 font=FONT_CARD_TITLE).pack(side="left")

        right = tk.Frame(header, bg=BG_CARD)
        right.pack(side="right")
        DarkButton(right, "SAVE", command=self._save, accent=True
                   ).pack(side="right", padx=2)
        DarkButton(right, "RESET TO DEFAULTS", command=self._reset
                   ).pack(side="right", padx=2)

        horizontal_separator(self.window).pack(fill="x")

        # Tab notebook
        nb = ttk.Notebook(self.window)
        nb.pack(fill="both", expand=True, padx=PAD_OUTER, pady=PAD_INNER)

        self._build_capture_tab(nb)
        self._build_analysis_tab(nb)
        self._build_reports_tab(nb)
        self._build_firewall_tab(nb)
        self._build_about_tab(nb)

        # Status bar
        self._status_bar = StatusBar(self.window)
        self._status_bar.pack(side="bottom", fill="x")

    # ── Capture Tab ───────────────────────────────────────────────────────────

    def _build_capture_tab(self, nb: ttk.Notebook) -> None:
        frame = tk.Frame(nb, bg=BG_DARK)
        nb.add(frame, text="  CAPTURE  ")

        p = tk.Frame(frame, bg=BG_DARK, padx=PAD_OUTER, pady=PAD_INNER)
        p.pack(fill="both", expand=True)

        # Default interface
        section_header(p, "Network Interface").pack(anchor="w",
                                                     pady=(0, PAD_SMALL))

        iface_frame = tk.Frame(p, bg=BG_DARK)
        iface_frame.pack(fill="x")

        tk.Label(iface_frame, text="Default Interface:", bg=BG_DARK,
                 fg=FG_SECONDARY, font=FONT_LABEL, width=22,
                 anchor="w").pack(side="left")

        iface_var = tk.StringVar()
        self._vars["default_interface"] = iface_var

        interfaces = get_available_interfaces()
        combo = ttk.Combobox(iface_frame, textvariable=iface_var,
                             values=[""] + interfaces, width=34)
        combo.pack(side="left", padx=PAD_SMALL)

        tk.Label(p, text="Leave blank to select manually at capture time.",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL).pack(anchor="w")

        horizontal_separator(p).pack(fill="x", pady=PAD_INNER)

        # Packet limits
        section_header(p, "Packet Display Limits").pack(anchor="w",
                                                         pady=(0, PAD_SMALL))

        self._spin_row(p, "max_visible_packets",
                       "Max rows in live table:", 100, 50000, 500)
        tk.Label(p,
                 text="Older rows are pruned once this limit is reached. "
                      "All packets are kept in memory and the database.",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL,
                 wraplength=560, justify="left").pack(anchor="w")

        horizontal_separator(p).pack(fill="x", pady=PAD_INNER)

        # Payload preview
        section_header(p, "Payload Preview").pack(anchor="w",
                                                   pady=(0, PAD_SMALL))

        self._spin_row(p, "payload_preview_bytes",
                       "Payload preview size (bytes):", 64, 8192, 64)
        tk.Label(p,
                 text="Controls how many bytes are shown in the ASCII/HEX/Binary "
                      "tabs when a packet is selected.",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL,
                 wraplength=560, justify="left").pack(anchor="w")

    # ── Analysis Tab ──────────────────────────────────────────────────────────

    def _build_analysis_tab(self, nb: ttk.Notebook) -> None:
        frame = tk.Frame(nb, bg=BG_DARK)
        nb.add(frame, text="  ANALYSIS  ")

        p = tk.Frame(frame, bg=BG_DARK, padx=PAD_OUTER, pady=PAD_INNER)
        p.pack(fill="both", expand=True)

        section_header(p, "Analysis Modules").pack(anchor="w",
                                                    pady=(0, PAD_SMALL))

        toggles = [
            ("enable_dns_analysis",
             "Enable DNS Analysis",
             "Track DNS queries and responses; show them in the Timeline."),
            ("enable_flow_tracking",
             "Enable Flow Tracking",
             "Group packets into bidirectional flows. Required for Flow "
             "Investigation and many rule-engine checks."),
            ("enable_anomaly_rules",
             "Enable Anomaly Rule Engine",
             "Run heuristic rules after capture to generate Findings. "
             "Disable to reduce CPU use during very high packet rates."),
        ]

        for key, label, desc in toggles:
            self._toggle_row(p, key, label, desc)
            p._nametowidget(p.winfo_children()[-1].winfo_name())  # spacer

        horizontal_separator(p).pack(fill="x", pady=PAD_INNER)

        section_header(p, "Risk Threshold").pack(anchor="w",
                                                  pady=(0, PAD_SMALL))

        thresh_frame = tk.Frame(p, bg=BG_DARK)
        thresh_frame.pack(fill="x")

        tk.Label(thresh_frame, text="Minimum severity to display:",
                 bg=BG_DARK, fg=FG_SECONDARY, font=FONT_LABEL,
                 width=26, anchor="w").pack(side="left")

        thresh_var = tk.StringVar()
        self._vars["risk_threshold"] = thresh_var

        ttk.Combobox(
            thresh_frame,
            textvariable=thresh_var,
            values=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            state="readonly", width=14,
        ).pack(side="left", padx=PAD_SMALL)

        tk.Label(p,
                 text="Findings below this severity will not appear in the "
                      "Alerts & Findings window.",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL,
                 wraplength=560, justify="left").pack(anchor="w")

    # ── Reports Tab ───────────────────────────────────────────────────────────

    def _build_reports_tab(self, nb: ttk.Notebook) -> None:
        frame = tk.Frame(nb, bg=BG_DARK)
        nb.add(frame, text="  REPORTS  ")

        p = tk.Frame(frame, bg=BG_DARK, padx=PAD_OUTER, pady=PAD_INNER)
        p.pack(fill="both", expand=True)

        section_header(p, "Export Directory").pack(anchor="w",
                                                    pady=(0, PAD_SMALL))

        dir_frame = tk.Frame(p, bg=BG_DARK)
        dir_frame.pack(fill="x")

        tk.Label(dir_frame, text="Default export path:", bg=BG_DARK,
                 fg=FG_SECONDARY, font=FONT_LABEL, width=22,
                 anchor="w").pack(side="left")

        dir_var = tk.StringVar()
        self._vars["export_directory"] = dir_var

        ttk.Entry(dir_frame, textvariable=dir_var, width=34
                  ).pack(side="left", padx=PAD_SMALL)

        DarkButton(dir_frame, "BROWSE",
                   command=lambda: self._browse_dir(dir_var)
                   ).pack(side="left")

        horizontal_separator(p).pack(fill="x", pady=PAD_INNER)

        section_header(p, "Default Report Content").pack(anchor="w",
                                                          pady=(0, PAD_SMALL))

        self._toggle_row(
            p, "include_payload_stats",
            "Include Payload Statistics",
            "Add payload size analysis section to all generated reports."
        )
        self._toggle_row(
            p, "include_analyst_notes",
            "Include Analyst Notes",
            "Add the analyst notes section to all generated reports."
        )

    # ── Firewall Tab ──────────────────────────────────────────────────────────

    def _build_firewall_tab(self, nb: ttk.Notebook) -> None:
        frame = tk.Frame(nb, bg=BG_DARK)
        nb.add(frame, text="  FIREWALL  ")

        p = tk.Frame(frame, bg=BG_DARK, padx=PAD_OUTER, pady=PAD_INNER)
        p.pack(fill="both", expand=True)

        # Platform status
        if IS_WINDOWS:
            is_admin = check_admin_privileges()
            status_text = (
                "● Running as Administrator — firewall controls available"
                if is_admin
                else "⚠ Not running as Administrator — firewall rules require elevation"
            )
            status_color = FG_SUCCESS if is_admin else FG_ACCENT
        else:
            status_text = "⚠ Windows Firewall integration is only available on Windows."
            status_color = FG_SECONDARY

        tk.Label(p, text=status_text, bg=BG_DARK, fg=status_color,
                 font=FONT_BODY, anchor="w").pack(anchor="w",
                                                   pady=(0, PAD_INNER))

        horizontal_separator(p).pack(fill="x", pady=PAD_SMALL)

        section_header(p, "Defensive Controls").pack(anchor="w",
                                                      pady=(0, PAD_SMALL))

        self._toggle_row(
            p, "enable_firewall_controls",
            "Enable Firewall Block Controls",
            "Show block/unblock buttons in the IP Investigation window. "
            "Requires Administrator privileges. "
            "This application only manages rules it created itself — "
            "it never modifies existing system firewall rules."
        )

        horizontal_separator(p).pack(fill="x", pady=PAD_INNER)

        section_header(p, "Application Firewall Rules").pack(anchor="w",
                                                              pady=(0, PAD_SMALL))

        tk.Label(p,
                 text="All rules created by this application use the prefix:\n"
                      "    PayloadCapture_Block_<IP>",
                 bg=BG_DARK, fg=FG_SECONDARY, font=FONT_MONO,
                 justify="left", anchor="w").pack(anchor="w")

        DarkButton(p, "VIEW APPLICATION RULES",
                   command=self._show_firewall_rules
                   ).pack(anchor="w", pady=PAD_INNER)

        tk.Label(p,
                 text="Rules can only be added and removed through this application. "
                      "They are visible in Windows Defender Firewall with Advanced Security "
                      "and can be removed manually there if needed.",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL,
                 wraplength=560, justify="left").pack(anchor="w")

    # ── About Tab ─────────────────────────────────────────────────────────────

    def _build_about_tab(self, nb: ttk.Notebook) -> None:
        frame = tk.Frame(nb, bg=BG_DARK)
        nb.add(frame, text="  ABOUT  ")

        p = tk.Frame(frame, bg=BG_DARK, padx=PAD_OUTER, pady=PAD_INNER)
        p.pack(fill="both", expand=True)

        tk.Label(p, text="PAYLOAD CAPTURE SUITE", bg=BG_DARK,
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(p, text="Network Monitoring  ·  Payload Analysis  ·  Digital Evidence",
                 bg=BG_DARK, fg=FG_SECONDARY, font=FONT_BODY).pack(anchor="w",
                                                                     pady=(0, PAD_INNER))

        horizontal_separator(p).pack(fill="x", pady=PAD_SMALL)

        about_fields = [
            ("Version",         "1.0.0  (Phases 1–5)"),
            ("Python required", "3.10 or newer"),
            ("Required packages","scapy  ·  reportlab (for PDF)"),
            ("Windows capture", "Npcap required — https://npcap.com"),
            ("Database",        "SQLite (data/payloadcapture.db)"),
            ("Settings file",   str(pathlib.Path.home() /
                                    ".payloadcapturesuite" / "settings.json")),
        ]

        for label, value in about_fields:
            row = tk.Frame(p, bg=BG_DARK)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg=BG_DARK, fg=FG_SECONDARY,
                     font=FONT_LABEL, width=22, anchor="w").pack(side="left")
            tk.Label(row, text=value, bg=BG_DARK, fg=FG_PRIMARY,
                     font=FONT_MONO, anchor="w").pack(side="left")

        horizontal_separator(p).pack(fill="x", pady=PAD_INNER)

        tk.Label(p,
                 text="For authorized network monitoring only.\n"
                      "Only capture traffic on networks and systems you own or "
                      "have explicit written permission to monitor.",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL,
                 justify="left", wraplength=560).pack(anchor="w")

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _spin_row(self, parent, key: str, label: str,
                  from_: int, to_: int, increment: int) -> None:
        """A label + Spinbox row for integer settings."""
        row = tk.Frame(parent, bg=BG_DARK)
        row.pack(fill="x", pady=2)

        tk.Label(row, text=label, bg=BG_DARK, fg=FG_SECONDARY,
                 font=FONT_LABEL, width=28, anchor="w").pack(side="left")

        var = tk.IntVar()
        self._vars[key] = var

        spin = tk.Spinbox(
            row, from_=from_, to=to_, increment=increment,
            textvariable=var, width=10,
            bg=BG_INPUT, fg=FG_PRIMARY, insertbackground=FG_PRIMARY,
            buttonbackground=BG_CARD, relief="flat",
            font=FONT_MONO,
        )
        spin.pack(side="left", padx=PAD_SMALL)

    def _toggle_row(self, parent, key: str,
                    label: str, description: str) -> None:
        """A Checkbutton row with description text below."""
        var = tk.BooleanVar()
        self._vars[key] = var

        chk = tk.Checkbutton(
            parent, text=label, variable=var,
            bg=BG_DARK, fg=FG_PRIMARY,
            selectcolor=BG_INPUT,
            activebackground=BG_DARK, activeforeground=FG_PRIMARY,
            font=FONT_BODY,
        )
        chk.pack(anchor="w")

        tk.Label(parent, text=description, bg=BG_DARK, fg=FG_MUTED,
                 font=FONT_SMALL, wraplength=540,
                 justify="left").pack(anchor="w", padx=(20, 0))

        # Tiny spacer
        tk.Frame(parent, bg=BG_DARK, height=4).pack()

    # ── Data Binding ──────────────────────────────────────────────────────────

    def _load_values(self) -> None:
        """Populate all Tk variables from the current settings dict."""
        for key, var in self._vars.items():
            value = settings.get(key)
            if value is not None:
                try:
                    var.set(value)
                except Exception:
                    pass   # type mismatch — leave default

    def _save(self) -> None:
        """Write all Tk variable values back to settings and save to disk."""
        for key, var in self._vars.items():
            try:
                settings.set_value(key, var.get())
            except Exception:
                pass

        settings.save()
        self._status_bar.set_status("Settings saved.", "active")
        messagebox.showinfo("Saved", "Settings saved successfully.",
                            parent=self.window)

    def _reset(self) -> None:
        """Reset all settings to their compiled-in defaults."""
        answer = messagebox.askyesno(
            "Reset Settings",
            "Reset all settings to their defaults?",
            parent=self.window
        )
        if not answer:
            return

        from config.settings import DEFAULTS
        for key, default_value in DEFAULTS.items():
            settings.set_value(key, default_value)

        self._load_values()
        settings.save()
        self._status_bar.set_status("Settings reset to defaults.", "idle")

    def _on_close(self) -> None:
        self.window.destroy()

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse_dir(self, var: tk.StringVar) -> None:
        chosen = filedialog.askdirectory(
            title="Select Export Directory",
            initialdir=var.get() or str(pathlib.Path.home()),
            parent=self.window,
        )
        if chosen:
            var.set(chosen)

    def _show_firewall_rules(self) -> None:
        """Open a small dialog listing all application firewall rules."""
        from firewall.windows_firewall import list_application_rules, IS_WINDOWS

        if not IS_WINDOWS:
            messagebox.showinfo(
                "Not Available",
                "Windows Firewall management is only available on Windows.",
                parent=self.window
            )
            return

        from ui.firewall_dialog import FirewallRulesDialog

        rules = list_application_rules()
        FirewallRulesDialog(self.window, rules)
