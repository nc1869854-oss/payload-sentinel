"""
config/theme.py

Shared visual constants for the Payload Capture Suite.

All windows import from here so the application looks consistent.
Changing a value here changes it everywhere.
"""

# ─── Colour Palette ──────────────────────────────────────────────────────────

# Backgrounds
BG_DARK       = "#0d1117"   # main window / panel background
BG_CARD       = "#161b22"   # card / widget container
BG_HEADER     = "#0d1117"   # top header bar
BG_SIDEBAR    = "#010409"   # sidebar (future use)
BG_INPUT      = "#21262d"   # text-entry fields
BG_TABLE_ROW  = "#161b22"   # even table rows
BG_TABLE_ALT  = "#1c2128"   # odd (alternating) rows
BG_SELECTED   = "#1f6feb"   # highlighted / selected row

# Foreground / text
FG_PRIMARY    = "#e6edf3"   # primary text
FG_SECONDARY  = "#8b949e"   # secondary / dimmed text
FG_ACCENT     = "#58a6ff"   # links, accent highlights
FG_SUCCESS    = "#3fb950"   # green  — healthy / active
FG_WARNING    = "#d29922"   # orange — medium risk / warning
FG_DANGER     = "#f85149"   # red    — high / critical
FG_INFO       = "#79c0ff"   # blue   — informational
FG_MUTED      = "#484f58"   # borders, separators

# Severity colours (maps severity label → colour)
SEVERITY_COLORS = {
    "INFO":     "#58a6ff",   # blue
    "LOW":      "#3fb950",   # green
    "MEDIUM":   "#d29922",   # orange
    "HIGH":     "#f85149",   # red
    "CRITICAL": "#ff0000",   # bright red
}

# Risk colours for packet table
RISK_COLORS = {
    "LOW":      "#3fb950",
    "MEDIUM":   "#d29922",
    "HIGH":     "#f85149",
    "CRITICAL": "#ff0000",
    "NONE":     "#8b949e",
}

# Status indicator colours
STATUS_ACTIVE   = "#3fb950"   # ● green
STATUS_IDLE     = "#8b949e"   # ● grey
STATUS_PAUSED   = "#d29922"   # ● orange
STATUS_ERROR    = "#f85149"   # ● red


# ─── Typography ──────────────────────────────────────────────────────────────

FONT_FAMILY     = "Consolas"       # monospace; good for IPs and data
FONT_FAMILY_UI  = "Segoe UI"       # proportional; good for labels

FONT_HEADER     = (FONT_FAMILY_UI, 22, "bold")
FONT_SUBHEADER  = (FONT_FAMILY_UI, 11)
FONT_CARD_TITLE = (FONT_FAMILY_UI, 10, "bold")
FONT_CARD_VALUE = (FONT_FAMILY_UI, 28, "bold")
FONT_LABEL      = (FONT_FAMILY_UI, 9)
FONT_BODY       = (FONT_FAMILY_UI, 10)
FONT_SMALL      = (FONT_FAMILY_UI, 8)
FONT_MONO       = (FONT_FAMILY,    9)
FONT_MONO_SMALL = (FONT_FAMILY,    8)
FONT_BUTTON     = (FONT_FAMILY_UI, 9,  "bold")
FONT_STATUS     = (FONT_FAMILY,    9)
FONT_TABLE      = (FONT_FAMILY,    9)
FONT_TABLE_HEAD = (FONT_FAMILY_UI, 9,  "bold")


# ─── Spacing ─────────────────────────────────────────────────────────────────

PAD_OUTER  = 16   # outer margin of windows
PAD_INNER  = 10   # inner padding inside cards
PAD_SMALL  = 6    # tight spacing between related elements
PAD_TINY   = 3    # minimal gaps


# ─── Sizes ───────────────────────────────────────────────────────────────────

BUTTON_HEIGHT   = 32    # standard button height in pixels
CARD_RADIUS     = 4     # used where tk supports it (ttk frames)
STATUS_BAR_H    = 24
TABLE_ROW_H     = 20


# ─── Window Geometry ─────────────────────────────────────────────────────────

MAIN_WINDOW_SIZE    = "1200x700"
CAPTURE_WINDOW_SIZE = "1400x800"
FLOW_WINDOW_SIZE    = "1200x700"
ALERT_WINDOW_SIZE   = "1100x650"
IP_WINDOW_SIZE      = "1000x600"
TIMELINE_WINDOW_SIZE= "1000x650"
REPORT_WINDOW_SIZE  = "1100x700"
SETTINGS_WINDOW_SIZE= "700x500"
