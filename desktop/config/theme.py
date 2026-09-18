"""
config/theme.py

Shared visual constants for the Payload Capture Suite.

All windows import from here so the application looks consistent.
Changing a value here changes it everywhere.
"""

# ─── Depth system (Cybermon palette) ─────────────────────────────────────────
# Five distinct background levels, three border weights, three text levels,
# one blue accent plus four status colours. No pure black anywhere.

D0 = "#060b12"   # window chrome / title strip
D1 = "#0b1220"   # sidebar + toolbar
D2 = "#0f1826"   # main workspace background
D3 = "#131f30"   # cards and panels
D4 = "#192840"   # elevated: inspectors, modals, tooltips
D5 = "#1e3050"   # hover / selected

B0 = "#162032"   # hairline separator
B1 = "#1e2e42"   # standard border
B2 = "#28405a"   # emphatic / focus ring


# ─── Colour Palette ──────────────────────────────────────────────────────────

# Backgrounds
BG_CHROME     = D0          # outer window chrome
BG_DARK       = D2          # main window / panel background
BG_CARD       = D3          # card / widget container
BG_HEADER     = D1          # top header bar
BG_SIDEBAR    = D1          # sidebar
BG_ELEVATED   = D4          # inspector / modal surface
BG_INPUT      = D4          # text-entry fields
BG_TABLE_ROW  = D3          # even table rows
BG_TABLE_ALT  = "#111c2c"   # odd (alternating) rows
BG_HOVER      = D5          # hover state
BG_SELECTED   = D5          # highlighted / selected row

# Foreground / text
FG_PRIMARY    = "#c4d4e8"   # primary text
FG_SECONDARY  = "#8195ad"   # secondary / dimmed text
FG_ACCENT     = "#2b96d4"   # links, accent highlights
FG_SUCCESS    = "#29a86a"   # green  — healthy / active
FG_WARNING    = "#d49a2b"   # orange — medium risk / warning
FG_DANGER     = "#d44f4f"   # red    — high / critical
FG_INFO       = "#7c86e0"   # indigo — informational
FG_MUTED      = "#475f78"   # borders, separators, disabled

# Borders (semantic aliases)
BORDER_HAIR   = B0
BORDER        = B1
BORDER_FOCUS  = B2

# Severity colours (maps severity label → colour)
SEVERITY_COLORS = {
    "INFO":     FG_INFO,
    "LOW":      FG_SUCCESS,
    "MEDIUM":   FG_WARNING,
    "HIGH":     FG_DANGER,
    "CRITICAL": "#f06060",
}

# Risk colours for packet table
RISK_COLORS = {
    "LOW":      FG_SUCCESS,
    "MEDIUM":   FG_WARNING,
    "HIGH":     FG_DANGER,
    "CRITICAL": "#f06060",
    "NONE":     FG_SECONDARY,
}

# Status indicator colours
STATUS_ACTIVE   = FG_SUCCESS
STATUS_IDLE     = FG_SECONDARY
STATUS_PAUSED   = FG_WARNING
STATUS_ERROR    = FG_DANGER



# ─── Typography ──────────────────────────────────────────────────────────────

FONT_FAMILY     = "Cascadia Mono"  # monospace; good for IPs and data
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
