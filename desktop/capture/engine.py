"""
capture/engine.py

Live packet capture using Scapy.

This module runs the Scapy sniffer in its own thread so the GUI
never blocks.  Captured packets are placed into a thread-safe queue;
the UI reads from the queue using root.after() on the main thread.

Architecture:

    capture thread
         │  (Scapy packet)
         ▼
    thread-safe queue   ← engine writes
         │
         ▼
    UI main thread      ← UI reads via root.after()
"""

import threading
import queue
import time


try:
    from scapy.sendrecv import sniff
    from scapy.config   import conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class CaptureEngine:
    """
    Manages one live capture session.

    Usage:
        engine = CaptureEngine(packet_queue)
        engine.start(interface="eth0", bpf_filter="tcp")
        # ...
        engine.stop()
    """

    def __init__(self, packet_queue: queue.Queue):
        """
        Parameters
        ----------
        packet_queue : thread-safe queue shared with the UI thread.
                       The engine puts raw Scapy packet objects here.
        """
        self._queue          = packet_queue
        self._thread         = None
        self._stop_event     = threading.Event()
        self._is_capturing   = False
        self._is_paused      = False
        self._packet_count   = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, interface: str = None, bpf_filter: str = "") -> None:
        """
        Begin capturing packets on the given interface.

        Parameters
        ----------
        interface  : network interface name (e.g. "eth0", "\\Device\\NPF_{...}")
                     None = Scapy default (usually the first available)
        bpf_filter : BPF filter string (e.g. "tcp port 80")
                     Empty string = capture everything
        """
        if self._is_capturing:
            return   # already running

        self._stop_event.clear()
        self._is_capturing = True
        self._is_paused    = False
        self._packet_count = 0

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, bpf_filter),
            daemon=True,       # thread dies when the main program exits
            name="CaptureThread"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the capture thread."""
        self._stop_event.set()
        self._is_capturing = False
        self._is_paused    = False

    def pause(self) -> None:
        """Pause packet processing (capture continues, packets are discarded)."""
        self._is_paused = True

    def resume(self) -> None:
        """Resume processing paused packets."""
        self._is_paused = False

    def is_capturing(self) -> bool:
        return self._is_capturing

    def is_paused(self) -> bool:
        return self._is_paused

    def packet_count(self) -> int:
        return self._packet_count

    # ── Internal ──────────────────────────────────────────────────────────────

    def _capture_loop(self, interface: str, bpf_filter: str) -> None:
        """
        Run inside the capture thread.

        Scapy's sniff() calls _on_packet() for every captured packet.
        We pass stop_filter so sniff() checks our stop event periodically.
        """
        try:
            sniff(
                iface=interface if interface else None,
                filter=bpf_filter if bpf_filter else "",
                prn=self._on_packet,
                stop_filter=self._should_stop,
                store=False,    # don't accumulate packets in memory
            )
        except Exception as e:
            # Put the error into the queue so the UI can show it
            self._queue.put(("error", str(e)))
        finally:
            self._is_capturing = False

    def _on_packet(self, packet) -> None:
        """
        Called by Scapy for every captured packet.
        Runs in the capture thread — do NOT touch Tkinter widgets here.
        """
        if self._is_paused:
            return

        self._packet_count += 1
        # Put a tuple so the UI knows what kind of message this is
        self._queue.put(("packet", packet))

    def _should_stop(self, packet) -> bool:
        """
        Scapy calls this after each packet.
        Return True to tell Scapy to stop sniffing.
        """
        return self._stop_event.is_set()


# ─── Interface discovery ──────────────────────────────────────────────────────

def get_available_interfaces() -> list[str]:
    """
    Return a list of network interface names available on this machine.

    Returns an empty list if Scapy is not available or if there is
    a permission error.
    """
    if not SCAPY_AVAILABLE:
        return []

    try:
        from scapy.interfaces import get_if_list
        interfaces = get_if_list()
        return interfaces if interfaces else []
    except Exception:
        return []


def get_interface_display_name(iface: str) -> str:
    """
    Return a user-friendly display name for a network interface.

    On Windows, Scapy interface names are long GUIDs.
    We try to get the friendlier name using Scapy's interface list.
    Falls back to the raw name if no friendly name is found.
    """
    if not SCAPY_AVAILABLE:
        return iface

    try:
        from scapy.interfaces import IFACES
        if iface in IFACES:
            iface_obj = IFACES[iface]
            # Scapy interface objects have a 'description' or 'name' attribute
            return getattr(iface_obj, "description", None) or \
                   getattr(iface_obj, "name", None) or iface
    except Exception:
        pass

    return iface
