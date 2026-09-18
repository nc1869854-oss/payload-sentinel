"""
ui/firewall_dialog.py

Firewall-related dialogs used in the Settings window and IP Investigation.

FirewallRulesDialog : lists all application-created firewall rules with
                      remove buttons.
FirewallBlockDialog : confirmation dialog shown before blocking an IP.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_DANGER, FG_MUTED,
    FONT_BODY, FONT_LABEL, FONT_CARD_TITLE, FONT_SMALL, FONT_MONO,
    PAD_OUTER, PAD_INNER, PAD_SMALL,
)
from ui.widgets import DarkButton, horizontal_separator, section_header
from firewall.windows_firewall import (
    IS_WINDOWS, list_application_rules, remove_rule,
    block_outbound, block_inbound, is_ip_blocked,
    check_admin_privileges, RULE_PREFIX,
)


class FirewallRulesDialog:
    """
    Small window listing all PayloadCapture firewall rules.
    Opened from Settings → Firewall tab.
    """

    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Application Firewall Rules")
        self.window.geometry("700x420")
        self.window.configure(bg=BG_DARK)
        self.window.grab_set()

        self._build_ui()
        self._load_rules()

    def _build_ui(self) -> None:
        header = tk.Frame(self.window, bg=BG_CARD, pady=PAD_SMALL, padx=PAD_OUTER)
        header.pack(fill="x")

        tk.Label(header, text="APPLICATION FIREWALL RULES", bg=BG_CARD,
                 fg=FG_ACCENT, font=FONT_CARD_TITLE).pack(side="left")
        DarkButton(header, "REFRESH", command=self._load_rules
                   ).pack(side="right")

        horizontal_separator(self.window).pack(fill="x")

        tk.Label(self.window,
                 text=f"Only rules with the prefix  {RULE_PREFIX}  are shown.",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL,
                 anchor="w").pack(fill="x", padx=PAD_OUTER, pady=PAD_SMALL)

        # Rules table
        frame = tk.Frame(self.window, bg=BG_DARK)
        frame.pack(fill="both", expand=True, padx=PAD_OUTER)

        cols = ("NAME", "DIRECTION", "REMOTE IP", "ENABLED")
        self._tree = ttk.Treeview(frame, columns=cols,
                                   show="headings", selectmode="browse")
        widths = {"NAME": 260, "DIRECTION": 90, "REMOTE IP": 130, "ENABLED": 70}
        for col in cols:
            self._tree.heading(col, text=col)
            self._tree.column(col, width=widths.get(col, 80), anchor="w")

        scroll = ttk.Scrollbar(frame, orient="vertical",
                                command=self._tree.yview)
        self._tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        # Buttons
        btn_row = tk.Frame(self.window, bg=BG_DARK)
        btn_row.pack(fill="x", padx=PAD_OUTER, pady=PAD_INNER)

        DarkButton(btn_row, "REMOVE SELECTED RULE",
                   command=self._remove_selected, danger=True
                   ).pack(side="left", padx=(0, PAD_SMALL))
        DarkButton(btn_row, "CLOSE",
                   command=self.window.destroy).pack(side="left")

        self._status = tk.Label(self.window, text="", bg=BG_DARK,
                                fg=FG_SECONDARY, font=FONT_SMALL, anchor="w")
        self._status.pack(fill="x", padx=PAD_OUTER)

    def _load_rules(self) -> None:
        self._tree.delete(*self._tree.get_children())

        if not IS_WINDOWS:
            self._status.configure(
                text="Windows Firewall management not available on this platform.")
            return

        rules = list_application_rules()
        for rule in rules:
            self._tree.insert("", "end", iid=rule.get("name", ""),
                              values=(
                                  rule.get("name", ""),
                                  rule.get("direction", ""),
                                  rule.get("remote_ip", ""),
                                  rule.get("enabled", ""),
                              ))

        count = len(rules)
        self._status.configure(
            text=f"{count} application rule{'s' if count != 1 else ''} found.")

    def _remove_selected(self) -> None:
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("No Selection",
                                   "Select a rule to remove.",
                                   parent=self.window)
            return

        rule_name = sel[0]
        answer = messagebox.askyesno(
            "Remove Rule",
            f"Remove firewall rule:\n\n{rule_name}\n\n"
            "Traffic to/from the associated IP will no longer be blocked.",
            parent=self.window
        )
        if not answer:
            return

        result = remove_rule(rule_name)
        if result["success"]:
            self._load_rules()
            messagebox.showinfo("Removed", result["message"],
                                parent=self.window)
        else:
            messagebox.showerror("Error", result["message"],
                                 parent=self.window)


class FirewallBlockDialog:
    """
    Confirmation dialog shown before blocking an IP.

    Shows full details of what will happen:
      - IP address
      - Direction (outbound / inbound / both)
      - Rule name that will be created
      - Reason entered by the analyst

    The analyst must explicitly confirm before any rule is created.
    """

    def __init__(self, parent, ip_address: str,
                 on_confirm=None):
        """
        Parameters
        ----------
        parent      : parent Tk window
        ip_address  : IP to block
        on_confirm  : callback(ip, direction, reason) called after confirmation
        """
        self.ip_address = ip_address
        self.on_confirm = on_confirm

        self.window = tk.Toplevel(parent)
        self.window.title("Block IP Address")
        self.window.geometry("520x380")
        self.window.configure(bg=BG_DARK)
        self.window.resizable(False, False)
        self.window.grab_set()

        self._build_ui()

    def _build_ui(self) -> None:
        p = tk.Frame(self.window, bg=BG_DARK, padx=PAD_OUTER, pady=PAD_INNER)
        p.pack(fill="both", expand=True)

        # Warning banner
        warn = tk.Frame(p, bg="#3d0000", padx=PAD_INNER, pady=PAD_SMALL)
        warn.pack(fill="x")
        tk.Label(warn, text="⚠  FIREWALL BLOCK", bg="#3d0000",
                 fg=FG_DANGER, font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(warn,
                 text="This will create a Windows Firewall rule. "
                      "Verify the IP before proceeding.",
                 bg="#3d0000", fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(anchor="w")

        tk.Frame(p, bg=BG_DARK, height=PAD_INNER).pack()

        # IP display
        tk.Label(p, text="IP Address to Block:", bg=BG_DARK,
                 fg=FG_SECONDARY, font=FONT_LABEL, anchor="w").pack(anchor="w")
        tk.Label(p, text=self.ip_address, bg=BG_DARK, fg=FG_DANGER,
                 font=(FONT_MONO[0], 16, "bold"), anchor="w").pack(anchor="w")

        tk.Frame(p, bg=BG_DARK, height=PAD_INNER).pack()

        # Direction
        tk.Label(p, text="Direction:", bg=BG_DARK,
                 fg=FG_SECONDARY, font=FONT_LABEL, anchor="w").pack(anchor="w")

        self._direction_var = tk.StringVar(value="outbound")
        for label, value in [("Block Outbound (recommended)",  "outbound"),
                              ("Block Inbound",                "inbound"),
                              ("Block Both Directions",        "both")]:
            tk.Radiobutton(
                p, text=label, variable=self._direction_var, value=value,
                bg=BG_DARK, fg=FG_PRIMARY, selectcolor=BG_INPUT,
                activebackground=BG_DARK, font=FONT_BODY,
            ).pack(anchor="w")

        tk.Frame(p, bg=BG_DARK, height=PAD_SMALL).pack()

        # Reason
        tk.Label(p, text="Reason (required):", bg=BG_DARK,
                 fg=FG_SECONDARY, font=FONT_LABEL, anchor="w").pack(anchor="w")

        self._reason_text = tk.Text(p, bg=BG_INPUT, fg=FG_PRIMARY,
                                     font=FONT_SMALL, height=3, wrap="word",
                                     relief="flat", bd=0)
        self._reason_text.pack(fill="x")

        # Rule name preview
        tk.Label(p, text="Rule name that will be created:",
                 bg=BG_DARK, fg=FG_MUTED, font=FONT_SMALL, anchor="w"
                 ).pack(anchor="w", pady=(PAD_SMALL, 0))
        safe_ip = self.ip_address.replace(":", "-")
        tk.Label(p, text=f"PayloadCapture_Block_{safe_ip}",
                 bg=BG_DARK, fg=FG_SECONDARY, font=FONT_MONO, anchor="w"
                 ).pack(anchor="w")

        # Buttons
        horizontal_separator(p).pack(fill="x", pady=PAD_INNER)

        btn_row = tk.Frame(p, bg=BG_DARK)
        btn_row.pack(fill="x")

        DarkButton(btn_row, "CONFIRM BLOCK",
                   command=self._confirm, danger=True
                   ).pack(side="left", padx=(0, PAD_SMALL))
        DarkButton(btn_row, "CANCEL",
                   command=self.window.destroy).pack(side="left")

    def _confirm(self) -> None:
        reason = self._reason_text.get("1.0", "end").strip()
        if not reason:
            messagebox.showwarning("Reason Required",
                                   "Please enter a reason for this block.",
                                   parent=self.window)
            return

        direction = self._direction_var.get()

        if not IS_WINDOWS:
            messagebox.showinfo(
                "Not Available",
                "Windows Firewall management is only available on Windows.",
                parent=self.window
            )
            self.window.destroy()
            return

        if not check_admin_privileges():
            messagebox.showerror(
                "Administrator Required",
                "Creating firewall rules requires Administrator privileges.\n"
                "Please restart the application as Administrator.",
                parent=self.window
            )
            return

        # Execute the block
        results = []
        if direction in ("outbound", "both"):
            results.append(block_outbound(self.ip_address, reason))
        if direction in ("inbound", "both"):
            results.append(block_inbound(self.ip_address, reason))

        success = all(r["success"] for r in results)
        messages = "\n".join(r["message"] for r in results)

        if success:
            if self.on_confirm:
                self.on_confirm(self.ip_address, direction, reason)
            messagebox.showinfo("Rule Created", messages, parent=self.window)
            self.window.destroy()
        else:
            messagebox.showerror("Error", messages, parent=self.window)
