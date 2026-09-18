"""
core/session.py

InvestigationSession — the central state object for one investigation.

Instead of scattering session counters and metadata across dozens of
global variables in different windows, every component that needs
session state imports and updates this object.

The object is intentionally simple — it is a data container, not a
controller. Windows subscribe to it by passing callbacks; the session
calls those callbacks when state changes.

Lifecycle:
    session = InvestigationSession.create(interface="eth0")
    session.start_capture()
    # ... packets arrive, caller updates counters ...
    session.on_packet(packet_size, payload_size)
    session.stop_capture()
    session.close()
"""

import datetime
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional
from config.logger import get_logger

log = get_logger(__name__)


# ── Finding lifecycle states ──────────────────────────────────────────────────

class FindingState:
    NEW          = "NEW"
    INVESTIGATING= "INVESTIGATING"
    CONFIRMED    = "CONFIRMED"
    DISMISSED    = "DISMISSED"
    RESOLVED     = "RESOLVED"


# ── Capture source ────────────────────────────────────────────────────────────

class CaptureSource:
    LIVE = "LIVE"
    PCAP = "PCAP"


# ── Session status ────────────────────────────────────────────────────────────

class SessionStatus:
    CREATED   = "CREATED"
    CAPTURING = "CAPTURING"
    PAUSED    = "PAUSED"
    STOPPED   = "STOPPED"
    CLOSED    = "CLOSED"


# ── InvestigationSession ──────────────────────────────────────────────────────

class InvestigationSession:
    """
    Central state for one investigation session.

    Thread-safe: counter updates use a lock so the capture thread
    and the UI thread can both update safely.
    """

    def __init__(self, session_id: str, interface: str = "",
                 capture_source: str = CaptureSource.LIVE,
                 analyst: str = "Analyst"):
        self.session_id     = session_id
        self.interface      = interface
        self.capture_source = capture_source
        self.analyst        = analyst

        self.created_at     = datetime.datetime.now()
        self.capture_start: Optional[datetime.datetime] = None
        self.capture_end:   Optional[datetime.datetime] = None

        self.status         = SessionStatus.CREATED

        # ── Counters (updated from capture thread via lock) ───────────────────
        self._lock          = threading.Lock()
        self._packet_count  = 0
        self._flow_count    = 0
        self._payload_bytes = 0
        self._alert_count   = 0
        self._finding_count = 0
        self._byte_count    = 0

        # ── Change callbacks ──────────────────────────────────────────────────
        # Windows register callbacks here so they refresh when state changes.
        # Callbacks are called from the main thread via root.after().
        self._on_stats_change: list[Callable] = []

        log.info("Session created: %s  interface=%s  source=%s",
                 session_id, interface, capture_source)

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(cls, interface: str = "",
               capture_source: str = CaptureSource.LIVE,
               analyst: str = "Analyst") -> "InvestigationSession":
        """Create a new session and persist it to the database."""
        import time
        from evidence.sessions import generate_session_id
        from evidence.database import create_session as db_create, get_session

        sid = generate_session_id()
        # Guard against duplicate IDs when tests call create() rapidly
        while get_session(sid) is not None:
            time.sleep(0.001)
            sid = generate_session_id()
        db_create(sid, interface=interface, analyst=analyst)

        session = cls(sid, interface=interface,
                      capture_source=capture_source, analyst=analyst)
        return session

    @classmethod
    def load(cls, session_id: str) -> Optional["InvestigationSession"]:
        """Load an existing session from the database."""
        from evidence.database import get_session
        row = get_session(session_id)
        if not row:
            return None

        s = cls(
            session_id=session_id,
            interface=row.get("interface", ""),
            capture_source=row.get("capture_mode", CaptureSource.LIVE),
            analyst=row.get("analyst", "Analyst"),
        )
        s.status            = SessionStatus.STOPPED
        s._packet_count     = row.get("total_packets", 0)
        s._flow_count       = row.get("total_flows", 0)
        s._alert_count      = row.get("total_alerts", 0)
        s._byte_count       = row.get("total_bytes", 0)

        # Restore timestamps
        try:
            s.created_at = datetime.datetime.fromisoformat(row["created_at"])
        except Exception:
            pass

        log.info("Session loaded: %s", session_id)
        return s

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start_capture(self) -> None:
        self.capture_start = datetime.datetime.now()
        self.status        = SessionStatus.CAPTURING
        log.info("[%s] Capture started", self.session_id)

    def pause_capture(self) -> None:
        self.status = SessionStatus.PAUSED
        log.info("[%s] Capture paused", self.session_id)

    def resume_capture(self) -> None:
        self.status = SessionStatus.CAPTURING
        log.info("[%s] Capture resumed", self.session_id)

    def stop_capture(self) -> None:
        self.capture_end = datetime.datetime.now()
        self.status      = SessionStatus.STOPPED
        log.info("[%s] Capture stopped  packets=%d",
                 self.session_id, self._packet_count)

    def close(self) -> None:
        from evidence.database import close_session, update_session_stats
        self.status = SessionStatus.CLOSED
        close_session(self.session_id)
        update_session_stats(
            self.session_id,
            self._packet_count,
            self._byte_count,
            self._flow_count,
            self._alert_count,
        )
        log.info("[%s] Session closed", self.session_id)

    # ── Counter updates (thread-safe) ─────────────────────────────────────────

    def on_packet(self, packet_size: int, payload_size: int) -> None:
        """Called by the capture pipeline for every parsed packet."""
        with self._lock:
            self._packet_count  += 1
            self._byte_count    += packet_size
            self._payload_bytes += payload_size

    def set_flow_count(self, count: int) -> None:
        with self._lock:
            self._flow_count = count

    def set_alert_count(self, count: int) -> None:
        with self._lock:
            self._alert_count = count

    def set_finding_count(self, count: int) -> None:
        with self._lock:
            self._finding_count = count

    # ── Read-only properties (safe to read from any thread) ───────────────────

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    @property
    def flow_count(self) -> int:
        with self._lock:
            return self._flow_count

    @property
    def payload_bytes(self) -> int:
        with self._lock:
            return self._payload_bytes

    @property
    def byte_count(self) -> int:
        with self._lock:
            return self._byte_count

    @property
    def alert_count(self) -> int:
        with self._lock:
            return self._alert_count

    @property
    def finding_count(self) -> int:
        with self._lock:
            return self._finding_count

    @property
    def duration(self) -> str:
        """Human-readable HH:MM:SS duration."""
        from evidence.sessions import format_duration
        if self.capture_start:
            end = self.capture_end or datetime.datetime.now()
            return format_duration(self.capture_start, end)
        return "—"

    @property
    def is_live(self) -> bool:
        return self.capture_source == CaptureSource.LIVE

    @property
    def source_label(self) -> str:
        return "LIVE CAPTURE" if self.is_live else "PCAP ANALYSIS"

    # ── Callback subscription ─────────────────────────────────────────────────

    def subscribe(self, callback: Callable) -> None:
        """Register a callback to be called when stats change."""
        self._on_stats_change.append(callback)

    def notify_subscribers(self) -> None:
        """
        Call all registered stat-change callbacks.
        Must be called from the Tkinter main thread.
        """
        for cb in self._on_stats_change:
            try:
                cb(self)
            except Exception as e:
                log.warning("Subscriber callback error: %s", e)

    # ── Audit trail ───────────────────────────────────────────────────────────

    def log_action(self, action: str, detail: str = "") -> None:
        """
        Record an analyst action in the audit trail.
        Persists to the database timeline_events table.
        """
        from evidence.database import get_connection
        import datetime as dt
        now = dt.datetime.now().isoformat(timespec="seconds")

        try:
            conn = get_connection()
            conn.execute(
                """INSERT INTO timeline_events
                   (session_id, event_time, event_type, description)
                   VALUES (?, ?, 'ACTION', ?)""",
                (self.session_id, now, f"{action}: {detail}" if detail else action)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning("Could not log action '%s': %s", action, e)

        log.info("[%s] ACTION: %s  %s", self.session_id, action, detail)

    def __repr__(self) -> str:
        return (f"InvestigationSession(id={self.session_id!r}, "
                f"status={self.status!r}, packets={self._packet_count})")
