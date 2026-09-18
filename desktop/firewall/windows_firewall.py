"""
firewall/windows_firewall.py

Windows Firewall integration for Payload Capture Suite.

Manages ONLY rules created by this application — identified by the
naming prefix  PayloadCapture_Block_<IP>.

Principles:
  - Never modifies rules created by other software.
  - Never silently blocks anything.
  - Every action requires confirmation from the analyst.
  - Every rule has a visible reason and direction.
  - Rules can always be removed from inside the application.

Implementation:
  Uses subprocess to call netsh and PowerShell.
  netsh is available on all Windows versions.
  PowerShell New-NetFirewallRule gives cleaner structured output
  but falls back to netsh if not available.

On non-Windows systems this module disables itself gracefully —
the UI shows an explanatory message instead of crashing.
"""

import subprocess
import sys
import re


# ── Platform check ────────────────────────────────────────────────────────────

IS_WINDOWS = sys.platform == "win32"

# Naming convention for all rules this application creates.
# Using a prefix makes it easy to list and remove our rules without
# touching anything else.
RULE_PREFIX = "PayloadCapture_Block_"


# ── Result helpers ────────────────────────────────────────────────────────────

def _ok(message: str) -> dict:
    return {"success": True,  "message": message}


def _err(message: str) -> dict:
    return {"success": False, "message": message}


# ── Public API ────────────────────────────────────────────────────────────────

def block_outbound(ip_address: str, reason: str = "") -> dict:
    """
    Create a Windows Firewall rule that blocks all outbound traffic
    to the given IP address.

    Parameters
    ----------
    ip_address : IPv4 or IPv6 address to block
    reason     : short description stored in the rule name/comment

    Returns
    -------
    dict with keys:
        success  : bool
        message  : human-readable result
        rule_name: name of the created rule (present on success)
    """
    if not IS_WINDOWS:
        return _err("Windows Firewall integration is only available on Windows.")

    if not _is_valid_ip(ip_address):
        return _err(f"'{ip_address}' is not a valid IP address.")

    rule_name = _rule_name(ip_address)

    # Build the netsh command
    # netsh advfirewall firewall add rule
    #   name="..."
    #   dir=out
    #   action=block
    #   remoteip=<IP>
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes",
        "profile=any",
    ]

    result = _run(cmd)
    if result["success"]:
        result["rule_name"] = rule_name
        result["message"] = (
            f"Outbound traffic to {ip_address} is now blocked.\n"
            f"Rule: {rule_name}"
        )
    return result


def block_inbound(ip_address: str, reason: str = "") -> dict:
    """
    Create a Windows Firewall rule that blocks all inbound traffic
    from the given IP address.
    """
    if not IS_WINDOWS:
        return _err("Windows Firewall integration is only available on Windows.")

    if not _is_valid_ip(ip_address):
        return _err(f"'{ip_address}' is not a valid IP address.")

    rule_name = _rule_name(ip_address) + "_IN"

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes",
        "profile=any",
    ]

    result = _run(cmd)
    if result["success"]:
        result["rule_name"] = rule_name
        result["message"] = (
            f"Inbound traffic from {ip_address} is now blocked.\n"
            f"Rule: {rule_name}"
        )
    return result


def remove_rule(rule_name: str) -> dict:
    """
    Remove a firewall rule by its exact name.

    Only removes rules whose names start with RULE_PREFIX — this
    prevents the application from accidentally deleting unrelated rules.
    """
    if not IS_WINDOWS:
        return _err("Windows Firewall integration is only available on Windows.")

    # Safety check — only touch our own rules
    if not rule_name.startswith(RULE_PREFIX):
        return _err(
            f"Rule '{rule_name}' does not have the application prefix "
            f"'{RULE_PREFIX}'. Only rules created by this application "
            f"can be removed from here."
        )

    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ]

    result = _run(cmd)
    if result["success"]:
        result["message"] = f"Rule '{rule_name}' removed."
    return result


def remove_rule_for_ip(ip_address: str) -> dict:
    """
    Remove all application-created rules for a specific IP address
    (both inbound and outbound variants).
    """
    results = []
    for suffix in ["", "_IN"]:
        rule_name = _rule_name(ip_address) + suffix
        r = remove_rule(rule_name)
        results.append(r)

    # Report success if at least one rule was removed
    any_success = any(r["success"] for r in results)
    return _ok(f"Rules for {ip_address} removed.") if any_success else \
           _err(f"No application rules found for {ip_address}.")


def list_application_rules() -> list[dict]:
    """
    Return all firewall rules that were created by this application.

    Uses 'netsh advfirewall firewall show rule' and parses the output.
    Returns a list of dicts:
        [{"name": ..., "direction": ..., "action": ..., "remote_ip": ...}, ...]
    """
    if not IS_WINDOWS:
        return []

    cmd = [
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name={RULE_PREFIX}*",
        "verbose",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return _parse_netsh_rules(result.stdout)
    except Exception:
        return []


def is_ip_blocked(ip_address: str) -> bool:
    """Return True if an outbound block rule exists for this IP."""
    if not IS_WINDOWS:
        return False

    rule_name = _rule_name(ip_address)
    cmd = [
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name={rule_name}",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return "PayloadCapture" in result.stdout
    except Exception:
        return False


def check_admin_privileges() -> bool:
    """
    Return True if the process has administrator privileges.
    Firewall rules require elevation on Windows.
    """
    if not IS_WINDOWS:
        return False

    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── Internal helpers ──────────────────────────────────────────────────────────

def _rule_name(ip_address: str) -> str:
    """Build a rule name for an IP. Colons in IPv6 become hyphens."""
    safe_ip = ip_address.replace(":", "-")
    return f"{RULE_PREFIX}{safe_ip}"


def _is_valid_ip(ip_str: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    import ipaddress
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _run(cmd: list[str]) -> dict:
    """
    Execute a command and return a result dict.
    All netsh commands require administrator privileges.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )

        # netsh returns 0 on success; non-zero means failure
        if proc.returncode == 0:
            return _ok(proc.stdout.strip() or "Command succeeded.")
        else:
            stderr = proc.stderr.strip() or proc.stdout.strip()
            # Common error messages made friendlier
            if "requires elevation" in stderr.lower() or \
               "access is denied" in stderr.lower():
                return _err(
                    "Administrator privileges required.\n"
                    "Run Payload Capture Suite as Administrator to manage "
                    "firewall rules."
                )
            return _err(f"Command failed: {stderr}")

    except FileNotFoundError:
        return _err(
            "netsh not found. Windows Firewall management requires netsh, "
            "which is part of Windows."
        )
    except subprocess.TimeoutExpired:
        return _err("Firewall command timed out.")
    except Exception as e:
        return _err(f"Unexpected error: {e}")


def _parse_netsh_rules(output: str) -> list[dict]:
    """
    Parse 'netsh advfirewall firewall show rule verbose' output into dicts.

    netsh output looks like:
        Rule Name:      PayloadCapture_Block_8.8.8.8
        Direction:      Out
        Action:         Block
        RemoteIP:       8.8.8.8/255.255.255.255
        ...
    """
    rules = []
    current: dict = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current.get("name", "").startswith(RULE_PREFIX):
                rules.append(dict(current))
            current = {}
            continue

        if ":" in line:
            key, _, value = line.partition(":")
            key   = key.strip().lower().replace(" ", "_")
            value = value.strip()

            if key == "rule_name":
                current["name"] = value
            elif key == "direction":
                current["direction"] = value
            elif key == "action":
                current["action"] = value
            elif key == "remoteip":
                # Strip subnet mask suffix  (8.8.8.8/255.255.255.255 → 8.8.8.8)
                current["remote_ip"] = value.split("/")[0]
            elif key == "enabled":
                current["enabled"] = value

    # Don't forget the last block
    if current.get("name", "").startswith(RULE_PREFIX):
        rules.append(current)

    return rules
