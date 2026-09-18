"""
config/owner.py

Ownership, contact and legal metadata for Payload Capture Suite.

Single source of truth used by the About screen, generated reports and
the installer scripts.
"""

APP_NAME     = "Payload Capture Suite"
APP_VERSION  = "2.0.0"
APP_TAGLINE  = "Offline network forensics and payload analysis"
APP_EDITION  = "Final Edition"

OWNER_NAME   = "Avimanyu Singh Chauhan"
OWNER_ROLE   = "Owner and Lead Developer"
OWNER_EMAIL  = "rockniraj311@gmail.com"
OWNER_HANDLE = "@avimanyusingh53"

SOCIAL_LINKS = [
    ("Instagram", "https://instagram.com/avimanyusingh53"),
    ("X (Twitter)", "https://x.com/avimanyusingh53"),
    ("GitHub", "https://github.com/avimanyusingh53"),
    ("YouTube", "https://youtube.com/@avimanyusingh53"),
    ("LinkedIn", "https://linkedin.com/in/avimanyusingh53"),
    ("Facebook", "https://facebook.com/avimanyusingh53"),
    ("Telegram", "https://t.me/avimanyusingh53"),
]

COPYRIGHT = f"© 2026 {OWNER_NAME}. All rights reserved."

# Documents shipped alongside the application (docs/ folder)
LEGAL_DOCUMENTS = [
    ("License",            "docs/LICENSE.md"),
    ("Privacy Policy",     "docs/PRIVACY_POLICY.md"),
    ("Disclaimer",         "docs/DISCLAIMER.md"),
    ("Do's and Don'ts",    "docs/DOS_AND_DONTS.md"),
    ("Terms of Use",       "docs/TERMS_OF_USE.md"),
    ("Legal and Compliance", "docs/LEGAL_COMPLIANCE.md"),
    ("Credits",            "docs/CREDITS.md"),
]

SHORT_NOTICE = (
    f"{APP_NAME} {APP_VERSION} — {APP_TAGLINE}\n"
    f"{OWNER_ROLE}: {OWNER_NAME} <{OWNER_EMAIL}>\n"
    f"Social: {OWNER_HANDLE}\n"
    "Runs fully offline. No API keys, accounts or telemetry.\n"
    "Capture traffic only on networks you own or are authorised to monitor."
)
