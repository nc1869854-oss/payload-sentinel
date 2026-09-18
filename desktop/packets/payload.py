"""
packets/payload.py

Payload inspection and analysis utilities.

These functions operate on raw bytes and return presentation-ready strings.
None of these results prove a payload is malicious — they are forensic
observations that help an analyst decide what to investigate further.
"""

import math
import hashlib


def bytes_to_ascii(data: bytes, max_bytes: int = 512) -> str:
    """
    Convert payload bytes to a printable ASCII string.

    Non-printable bytes are shown as dots (like Wireshark).
    This makes it easy to spot readable strings embedded in binary data.

    Example:
        b'\\x00\\x00GET /index.html'  →  '..GET /index.html'
    """
    preview = data[:max_bytes]
    result = []
    for byte in preview:
        if 32 <= byte <= 126:           # printable ASCII range
            result.append(chr(byte))
        else:
            result.append(".")          # replace non-printable with dot
    return "".join(result)


def bytes_to_hex(data: bytes, max_bytes: int = 512) -> str:
    """
    Convert payload bytes to a formatted hex dump.

    Groups of 16 bytes per line, space-separated.
    Matches the style analysts see in Wireshark or xxd.

    Example output:
        48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d
    """
    preview = data[:max_bytes]
    lines = []
    row_size = 16

    for offset in range(0, len(preview), row_size):
        chunk = preview[offset : offset + row_size]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad the hex part so short rows still align
        hex_part = hex_part.ljust(row_size * 3 - 1)
        lines.append(hex_part)

    return "\n".join(lines) if lines else "(no payload)"


def bytes_to_binary(data: bytes, max_bytes: int = 128) -> str:
    """
    Convert payload bytes to binary representation.

    Only shows the first max_bytes because binary expands 8x in size
    and quickly becomes unreadable beyond a few dozen bytes.
    """
    preview = data[:max_bytes]
    return " ".join(f"{b:08b}" for b in preview) if preview else "(no payload)"


def calculate_sha256(data: bytes) -> str:
    """
    Compute the SHA-256 hash of the payload.

    This hash can be used to:
    - Identify identical payloads across different packets
    - Verify that evidence has not been altered
    - Cross-reference with threat-intelligence databases (future feature)
    """
    return hashlib.sha256(data).hexdigest()


def calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of the payload (in bits per byte).

    Entropy measures how random or compressed data appears:
    - Low entropy  (0–3.0) : mostly printable text, patterns
    - Medium entropy (3–6) : structured binary, mixed content
    - High entropy  (6–8)  : compressed, encrypted, or random data

    Entropy alone cannot confirm encryption — compressed files
    also show high entropy. It is an investigation signal, not proof.
    """
    if not data:
        return 0.0

    # Count how often each byte value appears
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    total = len(data)
    entropy = 0.0

    for count in byte_counts:
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def calculate_printable_ratio(data: bytes) -> float:
    """
    Return the percentage of bytes that are printable ASCII (0–100.0).

    High ratio  → likely plain text or human-readable content
    Low ratio   → binary, compressed, or encrypted data
    """
    if not data:
        return 0.0

    printable_count = sum(1 for b in data if 32 <= b <= 126)
    return round(100.0 * printable_count / len(data), 1)


def calculate_null_byte_ratio(data: bytes) -> float:
    """
    Return the percentage of null bytes (0x00) in the payload (0–100.0).

    High null-byte ratio can indicate:
    - Binary data with padding
    - Wide-character strings (UTF-16/UTF-32)
    - Certain compression formats
    """
    if not data:
        return 0.0

    null_count = data.count(b"\x00")
    return round(100.0 * null_count / len(data), 1)


def analyse_payload(data: bytes) -> dict:
    """
    Run all payload analyses and return a summary dict.

    This is the main entry point called by the UI panels.
    """
    if not data:
        return {
            "size":              0,
            "sha256":            "(no payload)",
            "entropy":           0.0,
            "printable_ratio":   0.0,
            "null_byte_ratio":   0.0,
            "ascii_preview":     "(no payload)",
            "hex_dump":          "(no payload)",
            "binary_preview":    "(no payload)",
        }

    return {
        "size":              len(data),
        "sha256":            calculate_sha256(data),
        "entropy":           calculate_entropy(data),
        "printable_ratio":   calculate_printable_ratio(data),
        "null_byte_ratio":   calculate_null_byte_ratio(data),
        "ascii_preview":     bytes_to_ascii(data),
        "hex_dump":          bytes_to_hex(data),
        "binary_preview":    bytes_to_binary(data),
    }
