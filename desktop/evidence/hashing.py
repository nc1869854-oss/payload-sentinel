"""
evidence/hashing.py

SHA-256 file hashing for evidence integrity verification.

When a report or evidence package is exported, we calculate its hash
and record it in the database. The analyst can later verify that a
file has not been altered since export by comparing hashes.

This is standard practice in digital forensics — it establishes a
basic chain of custody for exported evidence.
"""

import hashlib
import pathlib
import datetime


def hash_file(file_path: str | pathlib.Path) -> str:
    """
    Compute the SHA-256 hash of a file.

    Reads in 64 KB chunks so large files don't fill RAM.

    Returns the hex digest string (64 lowercase hex characters).
    Raises FileNotFoundError if the file does not exist.
    """
    sha256 = hashlib.sha256()
    chunk_size = 65536   # 64 KB

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Compute the SHA-256 hash of a bytes object."""
    return hashlib.sha256(data).hexdigest()


def record_evidence_file(session_id: str, file_path: str | pathlib.Path,
                          file_type: str) -> dict:
    """
    Hash a file and record it in the evidence_files database table.

    Returns a dict with the file info and its hash, which can be
    displayed in the Report Center and included in reports.

    Parameters
    ----------
    session_id  : the investigation session this file belongs to
    file_path   : absolute path to the exported file
    file_type   : e.g. "HTML_REPORT", "PDF_REPORT", "CSV_EXPORT", "JSON_EXPORT"
    """
    path = pathlib.Path(file_path)

    sha256 = hash_file(path)
    filename = path.name
    now = datetime.datetime.now().isoformat(timespec="seconds")

    # Persist to database
    from evidence.database import get_connection
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO evidence_files
            (session_id, created_at, filename, file_path, file_type, sha256)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (session_id, now, filename, str(path), file_type, sha256)
    )
    conn.commit()
    conn.close()

    return {
        "session_id":  session_id,
        "created_at":  now,
        "filename":    filename,
        "file_path":   str(path),
        "file_type":   file_type,
        "sha256":      sha256,
    }


def verify_file(file_path: str | pathlib.Path, expected_hash: str) -> bool:
    """
    Verify that a file's current SHA-256 matches a previously recorded hash.

    Returns True if they match (file unaltered), False otherwise.
    """
    try:
        current_hash = hash_file(file_path)
        return current_hash.lower() == expected_hash.lower()
    except (FileNotFoundError, OSError):
        return False


def format_hash_display(sha256: str) -> str:
    """
    Format a SHA-256 hash for display — split into groups of 8 for readability.

    Example:
        "cd462990..." → "cd462990 f76d3085 6e1fd0f8 ..."
    """
    if not sha256 or len(sha256) < 64:
        return sha256 or "(not calculated)"
    return " ".join(sha256[i:i+8] for i in range(0, 64, 8))
