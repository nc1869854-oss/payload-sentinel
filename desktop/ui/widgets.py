"""
ui/widgets.py

Reusable Tkinter widget building blocks for Payload Capture Suite.

Importing from here keeps all visual components consistent and avoids
copy-pasting style code into every window.
"""

import tkinter as tk
from tkinter import ttk

from config.theme import (
    BG_DARK, BG_CARD, BG_INPUT, BG_TABLE_ROW, BG_TABLE_ALT, BG_SELECTED,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_WARNING, FG_DANGER,
    FG_MUTED, FONT_CARD_TITLE, FONT_CARD_VALUE, FONT_LABEL, FONT_BODY, FONT_BUTTON,
    FONT_MONO, FONT_SMALL, FONT_TABLE, FONT_TABLE_HEAD, FONT_STATUS,
    PAD_INNER, PAD_SMALL, SEVERITY_COLORS, RISK_COLORS,
    STATUS_ACTIVE, STATUS_IDLE, STATUS_PAUSED, STATUS_ERROR,
)


# ─── TTK Style Setup ──────────────────────────────────────────────────────────

def apply_dark_theme(root: tk.Tk) -> None:
    """
    Apply the dark SOC theme to a Tk root window.
    Call this once after creating the root.
    """
    style = ttk.Style(root)
    style.theme_use("clam")   # clam is most customisable

    # General frame background
    style.configure("TFrame",        background=BG_DARK)
    style.configure("Card.TFrame",   background=BG_CARD)
    style.configure("TLabel",        background=BG_DARK,  foreground=FG_PRIMARY,
                                     font=FONT_BODY)
    style.configure("Card.TLabel",   background=BG_CARD,  foreground=FG_PRIMARY,
                                     font=FONT_BODY)
    style.configure("Dim.TLabel",    background=BG_DARK,  foreground=FG_SECONDARY,
                                     font=FONT_SMALL)
    style.configure("Accent.TLabel", background=BG_DARK,  foreground=FG_ACCENT,
                                     font=FONT_BODY)

    # Notebook (tab container)
    style.configure("TNotebook",     background=BG_DARK,  borderwidth=0)
    style.configure("TNotebook.Tab", background=BG_CARD,  foreground=FG_SECONDARY,
                                     font=FONT_LABEL,  padding=[12, 6])
    style.map("TNotebook.Tab",
        background=[("selected", BG_DARK)],
        foreground=[("selected", FG_PRIMARY)],
    )

    # Treeview (packet table, flow table)
    style.configure("Treeview",
        background=BG_TABLE_ROW,
        foreground=FG_PRIMARY,
        fieldbackground=BG_TABLE_ROW,
        borderwidth=0,
        relief="flat",
        font=FONT_TABLE,
        rowheight=22,
    )
    style.configure("Treeview.Heading",
        background=BG_CARD,
        foreground=FG_SECONDARY,
        relief="flat",
        font=FONT_TABLE_HEAD,
    )
    style.map("Treeview",
        background=[("selected", BG_SELECTED)],
        foreground=[("selected", FG_PRIMARY)],
    )
    style.map("Treeview.Heading",
        background=[("active", BG_CARD)],
    )

    # Scrollbar
    style.configure("TScrollbar",
        background=BG_CARD,
        troughcolor=BG_DARK,
        arrowcolor=FG_MUTED,
        borderwidth=0,
    )

    # Entry
    style.configure("TEntry",
        fieldbackground=BG_INPUT,
        foreground=FG_PRIMARY,
        insertcolor=FG_PRIMARY,
        borderwidth=1,
        relief="flat",
        font=FONT_MONO,
    )

    # Combobox
    style.configure("TCombobox",
        fieldbackground=BG_INPUT,
        background=BG_CARD,
        foreground=FG_PRIMARY,
        arrowcolor=FG_SECONDARY,
        borderwidth=0,
        font=FONT_BODY,
    )
    style.map("TCombobox",
        fieldbackground=[("readonly", BG_INPUT)],
        foreground=[("readonly", FG_PRIMARY)],
    )

    # Separator
    style.configure("TSeparator", background=FG_MUTED)

    # Checkbutton
    style.configure("TCheckbutton",
        background=BG_DARK, foreground=FG_PRIMARY, font=FONT_BODY,
    )


# ─── Dark Button ─────────────────────────────────────────────────────────────

class DarkButton(tk.Button):
    """
    A flat, dark-styled button that fits the SOC aesthetic.

    Parameters
    ----------
    parent       : parent widget
    text         : button label
    command      : callback function
    accent       : True → blue accent colour; False → neutral grey
    danger       : True → red colour (destructive actions)
    """

    def __init__(self, parent, text: str, command=None,
                 accent: bool = False, danger: bool = False, **kwargs):

        if danger:
            bg, fg, hover = "#3d0000", FG_DANGER, "#5a0000"
        elif accent:
            bg, fg, hover = "#0d1b2a", FG_ACCENT, "#0f2035"
        else:
            bg, fg, hover = BG_CARD, FG_PRIMARY, "#1c2128"

        super().__init__(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
            font=FONT_BUTTON,
            cursor="hand2",
            **kwargs
        )

        # Hover effect
        self._bg_normal = bg
        self._bg_hover  = hover
        self.bind("<Enter>", lambda e: self.configure(bg=self._bg_hover))
        self.bind("<Leave>", lambda e: self.configure(bg=self._bg_normal))


# ─── Metric Card ─────────────────────────────────────────────────────────────

class MetricCard(tk.Frame):
    """
    A compact card showing a label and a large number.

    Example:
        ┌──────────────┐
        │  PACKETS     │
        │  125,482     │
        └──────────────┘
    """

    def __init__(self, parent, title: str, value: str = "0",
                 accent_color: str = FG_PRIMARY, **kwargs):
        super().__init__(parent, bg=BG_CARD, **kwargs)

        self.configure(padx=PAD_INNER, pady=PAD_INNER)

        self._title_label = tk.Label(
            self, text=title, bg=BG_CARD, fg=FG_SECONDARY,
            font=FONT_CARD_TITLE
        )
        self._title_label.pack(anchor="w")

        self._value_label = tk.Label(
            self, text=value, bg=BG_CARD, fg=accent_color,
            font=FONT_CARD_VALUE
        )
        self._value_label.pack(anchor="w")

    def set_value(self, value: str) -> None:
        """Update the displayed number."""
        self._value_label.configure(text=value)


# ─── Section Header ───────────────────────────────────────────────────────────

def section_header(parent, text: str, bg=BG_DARK) -> tk.Label:
    """Return a styled section-title label."""
    return tk.Label(
        parent, text=text.upper(), bg=bg, fg=FG_SECONDARY,
        font=FONT_CARD_TITLE, anchor="w"
    )


# ─── Detail Row ───────────────────────────────────────────────────────────────

def detail_row(parent, label: str, value: str, bg=BG_CARD) -> tuple:
    """
    Create a two-column label/value row inside a details panel.

    Returns (row_frame, value_label) so the caller can update value_label.
    """
    row = tk.Frame(parent, bg=bg)
    row.pack(fill="x", pady=1)

    lbl = tk.Label(row, text=label, bg=bg, fg=FG_SECONDARY,
                   font=FONT_SMALL, width=18, anchor="w")
    lbl.pack(side="left")

    val = tk.Label(row, text=value, bg=bg, fg=FG_PRIMARY,
                   font=FONT_MONO, anchor="w")
    val.pack(side="left", fill="x", expand=True)

    return row, val


# ─── Status Bar ───────────────────────────────────────────────────────────────

class StatusBar(tk.Frame):
    """
    A thin status bar at the bottom of each window.
    Shows a dot indicator, status text, and optional packet counter.
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG_CARD, height=26, **kwargs)
        self.pack_propagate(False)

        self._dot = tk.Label(self, text="●", bg=BG_CARD, fg=STATUS_IDLE,
                             font=FONT_STATUS)
        self._dot.pack(side="left", padx=(PAD_SMALL, 2))

        self._text = tk.Label(self, text="Ready", bg=BG_CARD, fg=FG_SECONDARY,
                              font=FONT_STATUS, anchor="w")
        self._text.pack(side="left", fill="x", expand=True)

        self._right = tk.Label(self, text="", bg=BG_CARD, fg=FG_SECONDARY,
                               font=FONT_STATUS, anchor="e")
        self._right.pack(side="right", padx=PAD_SMALL)

    def set_status(self, text: str, status: str = "idle") -> None:
        """
        Update the status bar.

        status values: "active", "idle", "paused", "error"
        """
        colour_map = {
            "active": STATUS_ACTIVE,
            "idle":   STATUS_IDLE,
            "paused": STATUS_PAUSED,
            "error":  STATUS_ERROR,
        }
        dot_color = colour_map.get(status, STATUS_IDLE)
        self._dot.configure(fg=dot_color)
        self._text.configure(text=text)

    def set_right(self, text: str) -> None:
        """Update the right-side counter text."""
        self._right.configure(text=text)


# ─── Separator ────────────────────────────────────────────────────────────────

def horizontal_separator(parent, bg=BG_DARK) -> tk.Frame:
    """A thin 1px horizontal rule."""
    return tk.Frame(parent, bg=FG_MUTED, height=1)


# ─── Risk Badge ───────────────────────────────────────────────────────────────

def risk_color(risk: str) -> str:
    """Return the foreground colour for a risk level string."""
    return RISK_COLORS.get(risk.upper(), FG_SECONDARY)


def severity_color(severity: str) -> str:
    """Return the foreground colour for a severity level string."""
    return SEVERITY_COLORS.get(severity.upper(), FG_SECONDARY)


# ─── Scrolled Text ────────────────────────────────────────────────────────────

class MonoText(tk.Frame):
    """
    A dark, read-only monospaced text area with a scrollbar.
    Used for payload ASCII/HEX/Binary display.
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG_CARD, **kwargs)

        self._text = tk.Text(
            self,
            bg=BG_CARD,
            fg=FG_PRIMARY,
            insertbackground=FG_PRIMARY,
            font=FONT_MONO,
            wrap="none",
            relief="flat",
            bd=0,
            state="disabled",   # read-only
            selectbackground=BG_SELECTED,
        )

        scroll_y = ttk.Scrollbar(self, orient="vertical",
                                 command=self._text.yview)
        scroll_x = ttk.Scrollbar(self, orient="horizontal",
                                 command=self._text.xview)

        self._text.configure(yscrollcommand=scroll_y.set,
                             xscrollcommand=scroll_x.set)

        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self._text.pack(fill="both", expand=True)

    def set_text(self, content: str) -> None:
        """Replace all text in the widget."""
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", content)
        self._text.configure(state="disabled")
        self._text.yview_moveto(0)   # scroll back to top


# ─── Module Launch Card ───────────────────────────────────────────────────────

class ModuleLaunchCard(tk.Frame):
    """
    Large clickable card used on the main dashboard launcher.

    Shows:
        TITLE
        Description text
        [ OPEN MODULE ] button
    """

    def __init__(self, parent, title: str, description: str,
                 button_text: str, command=None, **kwargs):
        super().__init__(parent, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER,
                         **kwargs)

        tk.Label(self, text=title, bg=BG_CARD, fg=FG_ACCENT,
                 font=FONT_CARD_TITLE, anchor="w").pack(anchor="w")

        tk.Label(self, text=description, bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_SMALL, wraplength=180, justify="left",
                 anchor="w").pack(anchor="w", pady=(4, 8))

        DarkButton(self, text=button_text, command=command,
                   accent=True).pack(anchor="w")


# ─── Packet Table ─────────────────────────────────────────────────────────────

PACKET_TABLE_COLUMNS = (
    "#", "TIME", "DIRECTION", "PROTOCOL",
    "SOURCE", "DESTINATION", "PORTS",
    "SIZE", "PAYLOAD", "RISK"
)

PACKET_COLUMN_WIDTHS = {
    "#":           65,
    "TIME":       110,
    "DIRECTION":   80,
    "PROTOCOL":    70,
    "SOURCE":      140,
    "DESTINATION": 140,
    "PORTS":       100,
    "SIZE":         70,
    "PAYLOAD":      70,
    "RISK":         70,
}


def build_packet_table(parent) -> ttk.Treeview:
    """
    Build and return a styled Treeview configured for the packet list.
    The caller is responsible for packing/gridding the returned widget.
    """
    columns = PACKET_TABLE_COLUMNS

    tree = ttk.Treeview(
        parent,
        columns=columns,
        show="headings",
        selectmode="extended",
    )

    # Row tags for alternating colours and risk highlighting
    tree.tag_configure("even",   background=BG_TABLE_ROW)
    tree.tag_configure("odd",    background=BG_TABLE_ALT)
    tree.tag_configure("risk_medium", foreground=FG_WARNING)
    tree.tag_configure("risk_high",   foreground=FG_DANGER)
    tree.tag_configure("risk_critical", foreground="#ff0000")

    for col in columns:
        width = PACKET_COLUMN_WIDTHS.get(col, 80)
        tree.heading(col, text=col, anchor="w")
        tree.column(col,  width=width, minwidth=40, anchor="w")

    return tree
