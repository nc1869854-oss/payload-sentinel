"""
ui/about_window.py

About / Owner screen with a built-in legal document reader.

Left side  — application identity, owner details, contact, social profiles.
Right side — a list of the bundled legal documents; selecting one renders it
             in the reading pane. Documents are plain Markdown files in docs/
             and are read from disk, so they stay correct after an edit and
             work identically in a PyInstaller bundle.

Fully offline: the only outbound action is handing a social-profile URL to the
system browser when the user clicks it.
"""

import pathlib
import sys
import tkinter as tk
import webbrowser
from tkinter import ttk, messagebox

from config.theme import (
    BG_DARK, BG_CARD, BG_HEADER, BG_ELEVATED, BG_HOVER,
    FG_PRIMARY, FG_SECONDARY, FG_ACCENT, FG_SUCCESS, FG_MUTED,
    FONT_HEADER, FONT_SUBHEADER, FONT_BODY, FONT_CARD_TITLE,
    FONT_SMALL, FONT_MONO, FONT_LABEL,
    PAD_OUTER, PAD_INNER, PAD_SMALL, PAD_TINY,
)
from config.owner import (
    APP_NAME, APP_VERSION, APP_TAGLINE, APP_EDITION,
    OWNER_NAME, OWNER_ROLE, OWNER_EMAIL, OWNER_HANDLE,
    SOCIAL_LINKS, COPYRIGHT, LEGAL_DOCUMENTS,
)
from ui.widgets import (
    apply_dark_theme, DarkButton, horizontal_separator, section_header,
)
from config.logger import get_logger

log = get_logger(__name__)

# Simple text glyphs stand in for icons — no image assets, no external fonts.
SOCIAL_GLYPHS = {
    "Instagram":   "◎",
    "X (Twitter)": "✕",
    "GitHub":      "⌘",
    "YouTube":     "▶",
    "LinkedIn":    "in",
    "Facebook":    "f",
    "Telegram":    "➤",
}

WINDOW_SIZE = "1060x700"


def _app_root() -> pathlib.Path:
    """
    Folder that holds docs/. Works both when running from source and when
    running from a PyInstaller one-folder/one-file bundle.
    """
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        return pathlib.Path(bundled)
    return pathlib.Path(__file__).resolve().parents[1]


class AboutWindow:
    """About, ownership and legal documents, in one window."""

    def __init__(self, parent):
        self.win = tk.Toplevel(parent)
        self.win.title(f"About — {APP_NAME} {APP_VERSION}")
        self.win.geometry(WINDOW_SIZE)
        self.win.configure(bg=BG_DARK)
        self.win.minsize(880, 560)
        apply_dark_theme(self.win)

        self._doc_buttons: dict[str, tk.Button] = {}
        self._current_doc: str | None = None

        self._build_header()

        body = tk.Frame(self.win, bg=BG_DARK)
        body.pack(fill="both", expand=True, padx=PAD_OUTER, pady=PAD_SMALL)
        body.columnconfigure(0, weight=0, minsize=330)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_identity_column(body)
        self._build_document_pane(body)

        footer = tk.Frame(self.win, bg=BG_HEADER)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer, text=COPYRIGHT, bg=BG_HEADER, fg=FG_MUTED,
                 font=FONT_SMALL).pack(side="left", padx=PAD_OUTER, pady=PAD_SMALL)
        DarkButton(footer, "CLOSE", command=self.win.destroy
                   ).pack(side="right", padx=PAD_OUTER, pady=PAD_SMALL)

        # Open on the first document so the pane is never blank.
        if LEGAL_DOCUMENTS:
            self._load_document(*LEGAL_DOCUMENTS[0])

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        header = tk.Frame(self.win, bg=BG_HEADER, pady=PAD_INNER)
        header.pack(fill="x")

        left = tk.Frame(header, bg=BG_HEADER)
        left.pack(side="left", padx=PAD_OUTER)
        tk.Label(left, text=APP_NAME.upper(), bg=BG_HEADER, fg=FG_ACCENT,
                 font=FONT_HEADER).pack(anchor="w")
        tk.Label(left, text=f"{APP_TAGLINE}  ·  {APP_EDITION}",
                 bg=BG_HEADER, fg=FG_SECONDARY,
                 font=FONT_SUBHEADER).pack(anchor="w")

        right = tk.Frame(header, bg=BG_HEADER)
        right.pack(side="right", padx=PAD_OUTER)
        tk.Label(right, text=f"VERSION {APP_VERSION}", bg=BG_HEADER,
                 fg=FG_PRIMARY, font=FONT_MONO).pack(anchor="e")
        tk.Label(right, text="● RUNS FULLY OFFLINE", bg=BG_HEADER,
                 fg=FG_SUCCESS, font=FONT_LABEL).pack(anchor="e", pady=(PAD_TINY, 0))

        horizontal_separator(self.win).pack(fill="x")

    # ── Identity column ───────────────────────────────────────────────────────

    def _build_identity_column(self, parent) -> None:
        column = tk.Frame(parent, bg=BG_DARK)
        column.grid(row=0, column=0, sticky="nsew", padx=(0, PAD_SMALL))

        # Owner card
        owner = tk.Frame(column, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        owner.pack(fill="x")
        tk.Label(owner, text="OWNER", bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(owner, text=OWNER_NAME, bg=BG_CARD, fg=FG_PRIMARY,
                 font=(FONT_SUBHEADER[0], 15, "bold")).pack(anchor="w", pady=(PAD_TINY, 0))
        tk.Label(owner, text=OWNER_ROLE, bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_BODY).pack(anchor="w")

        horizontal_separator(owner, bg=BG_CARD).pack(fill="x", pady=PAD_SMALL)

        self._contact_row(owner, "EMAIL", OWNER_EMAIL,
                          lambda: self._open_link(f"mailto:{OWNER_EMAIL}"))
        self._contact_row(owner, "SOCIAL HANDLE", OWNER_HANDLE, None)

        # Social card
        social = tk.Frame(column, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        social.pack(fill="x", pady=(PAD_SMALL, 0))
        tk.Label(social, text="SOCIAL PROFILES", bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(social, text=f"All profiles follow {OWNER_HANDLE}",
                 bg=BG_CARD, fg=FG_MUTED, font=FONT_SMALL
                 ).pack(anchor="w", pady=(0, PAD_SMALL))

        for name, url in SOCIAL_LINKS:
            self._social_row(social, name, url)

        # Offline notice
        notice = tk.Frame(column, bg=BG_CARD, padx=PAD_INNER, pady=PAD_INNER)
        notice.pack(fill="x", pady=(PAD_SMALL, 0))
        tk.Label(notice, text="NO KEYS · NO ACCOUNTS · NO TELEMETRY",
                 bg=BG_CARD, fg=FG_SUCCESS, font=FONT_CARD_TITLE).pack(anchor="w")
        tk.Label(
            notice,
            text=("Every detection, lookup and report is produced on this "
                  "computer from bundled data. Capture traffic only on "
                  "networks you own or are authorised to monitor."),
            bg=BG_CARD, fg=FG_SECONDARY, font=FONT_SMALL,
            wraplength=290, justify="left",
        ).pack(anchor="w", pady=(PAD_TINY, 0))

    def _contact_row(self, parent, label: str, value: str, command) -> None:
        row = tk.Frame(parent, bg=BG_CARD)
        row.pack(fill="x", pady=PAD_TINY)
        tk.Label(row, text=label, bg=BG_CARD, fg=FG_SECONDARY,
                 font=FONT_SMALL, width=15, anchor="w").pack(side="left")
        value_label = tk.Label(row, text=value, bg=BG_CARD,
                               fg=FG_ACCENT if command else FG_PRIMARY,
                               font=FONT_MONO, cursor="hand2" if command else "")
        value_label.pack(side="left")
        if command:
            value_label.bind("<Button-1>", lambda _e: command())

    def _social_row(self, parent, name: str, url: str) -> None:
        row = tk.Frame(parent, bg=BG_CARD, cursor="hand2")
        row.pack(fill="x", pady=1)

        glyph = tk.Label(row, text=SOCIAL_GLYPHS.get(name, "●"),
                         bg=BG_ELEVATED, fg=FG_ACCENT, font=FONT_BODY,
                         width=3, pady=2)
        glyph.pack(side="left", padx=(0, PAD_SMALL))
        name_label = tk.Label(row, text=name, bg=BG_CARD, fg=FG_PRIMARY,
                              font=FONT_BODY, anchor="w", width=13)
        name_label.pack(side="left")
        handle = tk.Label(row, text=OWNER_HANDLE, bg=BG_CARD, fg=FG_SECONDARY,
                          font=FONT_MONO, anchor="w")
        handle.pack(side="left")

        widgets = (row, glyph, name_label, handle)
        for widget in widgets:
            widget.bind("<Button-1>", lambda _e, u=url: self._open_link(u))
            widget.bind("<Enter>", lambda _e, w=widgets: self._hover(w, True))
            widget.bind("<Leave>", lambda _e, w=widgets: self._hover(w, False))

    @staticmethod
    def _hover(widgets, entering: bool) -> None:
        background = BG_HOVER if entering else BG_CARD
        for widget in widgets:
            if widget.cget("bg") in (BG_CARD, BG_HOVER):
                widget.configure(bg=background)

    # ── Document pane ─────────────────────────────────────────────────────────

    def _build_document_pane(self, parent) -> None:
        pane = tk.Frame(parent, bg=BG_DARK)
        pane.grid(row=0, column=1, sticky="nsew")
        pane.rowconfigure(2, weight=1)
        pane.columnconfigure(0, weight=1)

        section_header(pane, "LEGAL AND POLICY DOCUMENTS").grid(
            row=0, column=0, sticky="w")

        # Document selector strip
        strip = tk.Frame(pane, bg=BG_DARK)
        strip.grid(row=1, column=0, sticky="ew", pady=PAD_SMALL)
        for title, relative_path in LEGAL_DOCUMENTS:
            button = DarkButton(
                strip, title.upper(),
                command=lambda t=title, p=relative_path: self._load_document(t, p),
            )
            button.pack(side="left", padx=(0, PAD_TINY), pady=PAD_TINY)
            self._doc_buttons[title] = button

        # Reading surface
        surface = tk.Frame(pane, bg=BG_ELEVATED)
        surface.grid(row=2, column=0, sticky="nsew")
        surface.rowconfigure(1, weight=1)
        surface.columnconfigure(0, weight=1)

        self._doc_title = tk.Label(
            surface, text="", bg=BG_ELEVATED, fg=FG_ACCENT,
            font=FONT_CARD_TITLE, anchor="w", padx=PAD_INNER, pady=PAD_SMALL,
        )
        self._doc_title.grid(row=0, column=0, sticky="ew")

        text_frame = tk.Frame(surface, bg=BG_ELEVATED)
        text_frame.grid(row=1, column=0, sticky="nsew",
                        padx=PAD_INNER, pady=(0, PAD_INNER))
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)

        self._text = tk.Text(
            text_frame, bg=BG_ELEVATED, fg=FG_PRIMARY,
            font=FONT_MONO, relief="flat", wrap="word",
            insertbackground=FG_ACCENT, padx=PAD_SMALL, pady=PAD_SMALL,
            spacing1=1, spacing3=2,
        )
        self._text.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(text_frame, orient="vertical",
                                  command=self._text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self._text.configure(yscrollcommand=scrollbar.set)

        # Markdown-ish tags
        self._text.tag_configure("h1", foreground=FG_ACCENT,
                                 font=(FONT_SUBHEADER[0], 14, "bold"),
                                 spacing1=8, spacing3=4)
        self._text.tag_configure("h2", foreground=FG_PRIMARY,
                                 font=(FONT_SUBHEADER[0], 11, "bold"),
                                 spacing1=8, spacing3=3)
        self._text.tag_configure("bullet", foreground=FG_PRIMARY, lmargin1=18,
                                 lmargin2=30)
        self._text.tag_configure("dim", foreground=FG_SECONDARY)
        self._text.tag_configure("rule", foreground=FG_MUTED)

        actions = tk.Frame(pane, bg=BG_DARK)
        actions.grid(row=3, column=0, sticky="ew", pady=(PAD_SMALL, 0))
        DarkButton(actions, "OPEN DOCS FOLDER",
                   command=self._open_docs_folder).pack(side="left")
        self._doc_path_label = tk.Label(actions, text="", bg=BG_DARK,
                                        fg=FG_MUTED, font=FONT_SMALL)
        self._doc_path_label.pack(side="left", padx=PAD_SMALL)

    def _load_document(self, title: str, relative_path: str) -> None:
        path = _app_root() / relative_path
        self._current_doc = title
        self._doc_title.configure(text=title.upper())
        self._doc_path_label.configure(text=str(path))

        for name, button in self._doc_buttons.items():
            try:
                button.configure(fg=FG_ACCENT if name == title else FG_PRIMARY)
            except tk.TclError:                     # pragma: no cover
                pass

        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            content = (f"# {title} not found\n\n"
                       f"Expected the file at:\n\n{path}\n\n"
                       "Reinstall or restore the docs folder that ships with "
                       "the application.")
        except OSError as exc:
            log.warning("Could not read %s: %s", path, exc)
            content = f"# {title} could not be read\n\n{exc}"

        self._render_markdown(content)

    def _render_markdown(self, content: str) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")

        for raw_line in content.splitlines():
            line = raw_line.rstrip()
            if line.startswith("# "):
                self._text.insert("end", line[2:] + "\n", "h1")
            elif line.startswith("## ") or line.startswith("### "):
                self._text.insert("end", line.lstrip("# ") + "\n", "h2")
            elif line.strip() in ("---", "***", "___"):
                self._text.insert("end", "─" * 60 + "\n", "rule")
            elif line.lstrip().startswith(("- ", "* ")):
                self._text.insert("end", "  • " + line.lstrip()[2:] + "\n", "bullet")
            elif line.startswith(">"):
                self._text.insert("end", line.lstrip("> ") + "\n", "dim")
            else:
                self._text.insert("end", line + "\n")

        self._text.configure(state="disabled")
        self._text.yview_moveto(0.0)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _open_link(self, url: str) -> None:
        try:
            webbrowser.open_new_tab(url)
        except Exception as exc:                     # pragma: no cover
            log.warning("Could not open %s: %s", url, exc)
            messagebox.showinfo(
                "Link",
                f"Could not open the browser automatically.\n\nCopy this "
                f"address instead:\n{url}",
                parent=self.win,
            )

    def _open_docs_folder(self) -> None:
        folder = _app_root() / "docs"
        try:
            webbrowser.open(folder.as_uri())
        except Exception as exc:                     # pragma: no cover
            log.warning("Could not open docs folder: %s", exc)
            messagebox.showinfo("Documents folder", str(folder), parent=self.win)
