"""
capture/pcap.py

PCAP file import and export.

Import: Read a .pcap / .pcapng file using Scapy and feed the packets
        through the same parsing pipeline as live capture.  The UI
        displays PCAP ANALYSIS mode so the analyst knows this is not
        live traffic.

Export: Write the current session's captured packets back to a .pcap
        file so they can be loaded in Wireshark or shared with others.

Both operations require Scapy (and Npcap on Windows for live capture,
but NOT for reading existing pcap files — Scapy can read pcap files
without Npcap).
"""

import pathlib
import queue
import threading
from typing import Callable

try:
    from scapy.utils import rdpcap, wrpcap
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ── PCAP Import ───────────────────────────────────────────────────────────────

class PcapImporter:
    """
    Read packets from a .pcap or .pcapng file and feed them into a queue,
    exactly like the live CaptureEngine does.

    This lets the rest of the application treat imported PCAP traffic
    identically to live-captured traffic — same parser, same flow tracker,
    same rule engine, same UI.

    Usage:
        importer = PcapImporter(packet_queue)
        count, error = importer.import_file("/path/to/capture.pcap")
    """

    def __init__(self, packet_queue: queue.Queue):
        self._queue      = packet_queue
        self._cancelled  = threading.Event()

    def import_file(self, file_path: str | pathlib.Path,
                    progress_callback: Callable[[int, int], None] = None
                    ) -> tuple[int, str]:
        """
        Load all packets from a pcap file into the shared queue.

        Parameters
        ----------
        file_path         : path to the .pcap / .pcapng file
        progress_callback : optional fn(packets_loaded, total_packets)

        Returns
        -------
        (packet_count, error_message)
        error_message is empty string on success.
        """
        if not SCAPY_AVAILABLE:
            return 0, ("Scapy is required to read PCAP files.\n"
                       "Install it with:  pip install scapy")

        path = pathlib.Path(file_path)
        if not path.exists():
            return 0, f"File not found: {path}"

        # ── Validate the file before attempting to parse it ───────────────
        # A truncated or non-PCAP file produces a confusing Scapy traceback.
        # Check the magic number and minimum size up front so the user gets
        # a clear, actionable message instead.
        try:
            file_size = path.stat().st_size
        except OSError as e:
            return 0, f"Cannot access file: {e}"

        if file_size == 0:
            return 0, "The file is empty (0 bytes). Nothing to import."

        # Read the first 4 bytes to check the PCAP / PCAPng magic number.
        PCAP_MAGIC   = b"\xd4\xc3\xb2\xa1"   # little-endian classic
        PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"  # big-endian classic
        PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"   # pcapng (same both endians)
        try:
            with open(path, "rb") as fh:
                header = fh.read(4)
        except OSError as e:
            return 0, f"Cannot read file header: {e}"

        if header not in (PCAP_MAGIC, PCAP_MAGIC_BE, PCAPNG_MAGIC):
            return 0, (
                "This does not look like a valid PCAP or PCAPng file.\n"
                "The file header does not match any known capture format.\n"
                "The file may be corrupt, in a different format, or a "
                "text export rather than a binary capture."
            )

        try:
            # rdpcap loads all packets into memory.
            # For very large files (>500 MB) this can be slow — a future
            # improvement would use PcapReader for streaming.
            packets = rdpcap(str(path))
        except Exception as e:
            msg = str(e)
            # Distinguish truncation from other parse failures
            if "truncated" in msg.lower() or "unexpected eof" in msg.lower():
                return 0, (
                    "The file appears to be truncated or corrupt — the "
                    "capture ended before the last packet was fully written.\n"
                    f"Parser error: {msg}"
                )
            return 0, f"Could not read PCAP file: {msg}"

        total = len(packets)
        loaded = 0

        for pkt in packets:
            if self._cancelled.is_set():
                break

            self._queue.put(("packet", pkt))
            loaded += 1

            if progress_callback and loaded % 100 == 0:
                progress_callback(loaded, total)

        # Signal completion
        self._queue.put(("pcap_done", loaded))

        return loaded, ""

    def cancel(self) -> None:
        """Stop importing (used if the analyst closes the window mid-import)."""
        self._cancelled.set()


def import_pcap_threaded(file_path: str | pathlib.Path,
                         packet_queue: queue.Queue,
                         progress_callback: Callable = None) -> PcapImporter:
    """
    Start a PCAP import in a background thread.

    Returns the PcapImporter instance (call .cancel() to abort).
    The caller reads packets from packet_queue as normal.
    """
    importer = PcapImporter(packet_queue)

    thread = threading.Thread(
        target=importer.import_file,
        args=(file_path, progress_callback),
        daemon=True,
        name="PcapImportThread",
    )
    thread.start()

    return importer


# ── PCAP Export ───────────────────────────────────────────────────────────────

def export_pcap(raw_packets: list, output_path: str | pathlib.Path) -> tuple[bool, str]:
    """
    Write a list of raw Scapy packet objects to a .pcap file.

    Parameters
    ----------
    raw_packets : list of Scapy Packet objects (not parsed dicts)
    output_path : destination file path

    Returns
    -------
    (success, message)
    """
    if not SCAPY_AVAILABLE:
        return False, ("Scapy is required to write PCAP files.\n"
                       "Install it with:  pip install scapy")

    if not raw_packets:
        return False, "No packets to export."

    path = pathlib.Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        wrpcap(str(path), raw_packets)
        return True, str(path)
    except Exception as e:
        return False, f"Could not write PCAP file: {e}"


def get_pcap_info(file_path: str | pathlib.Path) -> dict:
    """
    Read basic metadata from a PCAP file without importing all packets.
    Used to show a preview before the analyst commits to a full import.

    Returns a dict with:
        packet_count : int
        file_size    : int (bytes)
        first_time   : str (ISO timestamp of first packet, if available)
        last_time    : str (ISO timestamp of last packet, if available)
        error        : str (empty on success)
    """
    result = {
        "packet_count": 0,
        "file_size":    0,
        "first_time":   "",
        "last_time":    "",
        "error":        "",
    }

    if not SCAPY_AVAILABLE:
        result["error"] = "Scapy not available."
        return result

    path = pathlib.Path(file_path)
    if not path.exists():
        result["error"] = f"File not found: {path}"
        return result

    result["file_size"] = path.stat().st_size

    # Validate the magic number before attempting a full parse.
    PCAP_MAGIC    = b"\xd4\xc3\xb2\xa1"
    PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
    PCAPNG_MAGIC  = b"\x0a\x0d\x0d\x0a"
    try:
        with open(path, "rb") as fh:
            header = fh.read(4)
    except OSError:
        header = b""
    if header and header not in (PCAP_MAGIC, PCAP_MAGIC_BE, PCAPNG_MAGIC):
        result["error"] = (
            "Not a valid PCAP or PCAPng file — header does not match."
        )
        return result

    try:
        packets = rdpcap(str(path))
        result["packet_count"] = len(packets)

        import datetime
        if packets:
            try:
                first_ts = float(packets[0].time)
                last_ts  = float(packets[-1].time)
                result["first_time"] = datetime.datetime.fromtimestamp(
                    first_ts).isoformat(timespec="seconds")
                result["last_time"]  = datetime.datetime.fromtimestamp(
                    last_ts).isoformat(timespec="seconds")
            except Exception:
                pass

    except Exception as e:
        result["error"] = f"Could not read file: {e}"

    return result
