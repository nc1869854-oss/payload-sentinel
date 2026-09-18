"""
tests/test_suite.py

Payload Capture Suite — test suite.

Run with:
    python -m pytest tests/test_suite.py -v
  or
    python tests/test_suite.py   (no pytest needed)

Tests use only synthetic data — no live network traffic required.
"""

import sys
import pathlib
import datetime
import json
import tempfile
import unittest

# Make sure the project root is on the path
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


# ─── Synthetic packet factory ─────────────────────────────────────────────────

def _make_packet(n, proto="TCP", src="10.0.0.1", dst="8.8.8.8",
                 sport=50000, dport=443, size=1400, payload=1350,
                 direction="OUTGOING", is_dns=False, dns_q=None):
    """Create a minimal parsed packet dict — matches the parser output format."""
    now = datetime.datetime.now()
    t = (now + datetime.timedelta(seconds=n * 0.1)).isoformat(timespec="milliseconds")
    return {
        "packet_number":  n,
        "capture_time":   t,
        "protocol":       proto,
        "src_ip":         src,
        "dst_ip":         dst,
        "src_port":       sport,
        "dst_port":       dport,
        "packet_size":    size,
        "payload_size":   payload,
        "direction":      direction,
        "risk_level":     "NONE",
        "flow_id":        f"{proto}-{min(src,dst)}:{sport}-{max(src,dst)}:{dport}",
        "is_dns":         is_dns,
        "dns_query":      dns_q,
        "dns_response":   None,
        "protocol_stack": [proto],
        "raw_summary":    proto,
    }


# ─── 1. Payload analysis ──────────────────────────────────────────────────────

class TestPayloadAnalysis(unittest.TestCase):

    def test_ascii_printable_text(self):
        from packets.payload import bytes_to_ascii, calculate_printable_ratio
        data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
        ascii_out = bytes_to_ascii(data)
        self.assertIn("GET", ascii_out)
        self.assertIn("example.com", ascii_out)
        ratio = calculate_printable_ratio(data)
        self.assertGreater(ratio, 80.0)

    def test_binary_payload(self):
        from packets.payload import calculate_printable_ratio, calculate_entropy
        data = bytes(range(256))
        ratio = calculate_printable_ratio(data)
        self.assertLess(ratio, 50.0)
        entropy = calculate_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=1)

    def test_empty_payload(self):
        from packets.payload import analyse_payload
        result = analyse_payload(b"")
        self.assertEqual(result["size"], 0)
        self.assertEqual(result["entropy"], 0.0)

    def test_sha256_consistency(self):
        from packets.payload import calculate_sha256
        data = b"hello world"
        h1 = calculate_sha256(data)
        h2 = calculate_sha256(data)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_hex_dump_format(self):
        from packets.payload import bytes_to_hex
        data = bytes(range(20))
        dump = bytes_to_hex(data)
        lines = dump.strip().split("\n")
        self.assertGreater(len(lines), 0)
        # Each hex byte is 2 chars + space
        self.assertIn("00", lines[0])

    def test_null_byte_ratio(self):
        from packets.payload import calculate_null_byte_ratio
        data = b"\x00" * 50 + b"A" * 50
        ratio = calculate_null_byte_ratio(data)
        self.assertAlmostEqual(ratio, 50.0, places=0)


# ─── 2. Packet parser ─────────────────────────────────────────────────────────

class TestPacketParser(unittest.TestCase):

    def test_direction_outgoing(self):
        from packets.parser import _determine_direction
        self.assertEqual(_determine_direction("10.0.0.1", "8.8.8.8", "10.0.0.1"), "OUTGOING")

    def test_direction_incoming(self):
        from packets.parser import _determine_direction
        self.assertEqual(_determine_direction("8.8.8.8", "10.0.0.1", "10.0.0.1"), "INCOMING")

    def test_direction_internal(self):
        from packets.parser import _determine_direction
        result = _determine_direction("192.168.1.1", "192.168.1.2", "")
        self.assertEqual(result, "INTERNAL")

    def test_private_ip_detection(self):
        from packets.parser import _is_private
        self.assertTrue(_is_private("192.168.1.1"))
        self.assertTrue(_is_private("10.0.0.1"))
        self.assertTrue(_is_private("172.16.0.1"))
        self.assertFalse(_is_private("8.8.8.8"))
        self.assertFalse(_is_private("1.1.1.1"))

    def test_flow_id_symmetric(self):
        from packets.parser import _make_flow_id
        id1 = _make_flow_id("10.0.0.1", 50000, "8.8.8.8", 443, "TCP")
        id2 = _make_flow_id("8.8.8.8",  443,   "10.0.0.1", 50000, "TCP")
        self.assertEqual(id1, id2)

    def test_flow_id_contains_protocol(self):
        from packets.parser import _make_flow_id
        fid = _make_flow_id("10.0.0.1", 100, "8.8.8.8", 200, "UDP")
        self.assertIn("UDP", fid)

    def test_invalid_ip_handled(self):
        from packets.parser import _is_private
        self.assertFalse(_is_private("not.an.ip"))
        self.assertFalse(_is_private("999.999.999.999"))


# ─── 3. IP classification ─────────────────────────────────────────────────────

class TestIPClassification(unittest.TestCase):

    def test_public_ip(self):
        from investigation.ip import classify_ip
        info = classify_ip("8.8.8.8")
        self.assertEqual(info["ip_type"], "PUBLIC")
        self.assertEqual(info["version"], 4)
        self.assertTrue(info["is_global"])
        self.assertFalse(info["is_private"])

    def test_private_ip(self):
        from investigation.ip import classify_ip
        for ip in ["192.168.1.1", "10.0.0.1", "172.16.0.1"]:
            info = classify_ip(ip)
            self.assertEqual(info["ip_type"], "PRIVATE", f"Failed for {ip}")

    def test_loopback(self):
        from investigation.ip import classify_ip
        info = classify_ip("127.0.0.1")
        self.assertEqual(info["ip_type"], "LOOPBACK")

    def test_ipv6_public(self):
        from investigation.ip import classify_ip
        info = classify_ip("2001:4860:4860::8888")
        self.assertEqual(info["version"], 6)

    def test_invalid_ip(self):
        from investigation.ip import classify_ip
        info = classify_ip("not.valid")
        self.assertEqual(info["ip_type"], "UNKNOWN")

    def test_ip_sort_order(self):
        from investigation.ip import get_all_ip_addresses
        packets = [
            _make_packet(1, src="10.0.0.3", dst="8.8.8.8"),
            _make_packet(2, src="10.0.0.1", dst="1.1.1.1"),
            _make_packet(3, src="10.0.0.2", dst="8.8.4.4"),
        ]
        ips = get_all_ip_addresses(packets)
        # Should be sorted numerically
        self.assertLess(ips.index("1.1.1.1"), ips.index("8.8.8.8"))


# ─── 4. Flow tracker ─────────────────────────────────────────────────────────

class TestFlowTracker(unittest.TestCase):

    def setUp(self):
        from flows.tracker import FlowTracker
        self.tracker = FlowTracker()

    def test_creates_flow(self):
        p = _make_packet(1, proto="TCP", src="10.0.0.1", dst="8.8.8.8")
        self.tracker.update(p)
        self.assertEqual(self.tracker.flow_count(), 1)

    def test_bidirectional_same_flow(self):
        p1 = _make_packet(1, proto="TCP", src="10.0.0.1", dst="8.8.8.8",
                          sport=50000, dport=443)
        p2 = _make_packet(2, proto="TCP", src="8.8.8.8", dst="10.0.0.1",
                          sport=443, dport=50000)
        self.tracker.update(p1)
        self.tracker.update(p2)
        # Both directions belong to the same flow
        self.assertEqual(self.tracker.flow_count(), 1)

    def test_packet_count_accumulates(self):
        for i in range(10):
            self.tracker.update(_make_packet(i))
        flows = self.tracker.get_all_flows()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["packet_count"], 10)

    def test_multiple_flows(self):
        self.tracker.update(_make_packet(1, dst="8.8.8.8"))
        self.tracker.update(_make_packet(2, dst="1.1.1.1"))
        self.tracker.update(_make_packet(3, dst="4.4.4.4"))
        self.assertEqual(self.tracker.flow_count(), 3)

    def test_clear(self):
        self.tracker.update(_make_packet(1))
        self.tracker.clear()
        self.assertEqual(self.tracker.flow_count(), 0)

    def test_flows_for_ip(self):
        self.tracker.update(_make_packet(1, src="10.0.0.1", dst="8.8.8.8"))
        self.tracker.update(_make_packet(2, src="10.0.0.1", dst="1.1.1.1"))
        self.tracker.update(_make_packet(3, src="192.168.1.1", dst="4.4.4.4"))
        flows = self.tracker.get_flows_for_ip("10.0.0.1")
        self.assertEqual(len(flows), 2)


# ─── 5. Rule engine ───────────────────────────────────────────────────────────

class TestRuleEngine(unittest.TestCase):

    def _make_session(self, packets, flows):
        from analysis.rules import run_all_rules
        return run_all_rules(packets, flows)

    def test_dns_volume_rule(self):
        """100+ DNS packets from same host should trigger the DNS volume rule."""
        packets = [
            _make_packet(i, proto="DNS", src="10.0.0.1", dst="8.8.8.8",
                         sport=53100+i, dport=53, size=80, payload=40,
                         is_dns=True, dns_q=f"domain{i}.example.com")
            for i in range(120)
        ]
        from flows.tracker import FlowTracker
        tracker = FlowTracker()
        for p in packets:
            tracker.update(p)
        findings = self._make_session(packets, tracker.get_all_flows())
        titles = [f["title"] for f in findings]
        self.assertTrue(any("DNS" in t for t in titles),
                        f"Expected DNS rule to fire. Got: {titles}")

    def test_icmp_flood_rule(self):
        """55 ICMP packets from same host should trigger ICMP rule."""
        packets = [
            _make_packet(i, proto="ICMP", src="10.0.0.1", dst="192.168.1.1",
                         sport=0, dport=0, size=64, payload=0)
            for i in range(55)
        ]
        from flows.tracker import FlowTracker
        tracker = FlowTracker()
        for p in packets:
            tracker.update(p)
        findings = self._make_session(packets, tracker.get_all_flows())
        titles = [f["title"] for f in findings]
        self.assertTrue(any("ICMP" in t for t in titles))

    def test_large_payload_rule(self):
        """Single packet with >8KB payload should trigger large-payload rule."""
        packets = [_make_packet(1, size=12000, payload=11500)]
        findings = self._make_session(packets, [])
        titles = [f["title"] for f in findings]
        self.assertTrue(any("Payload" in t for t in titles))

    def test_no_false_positives_normal_traffic(self):
        """Small normal session should generate zero or very few findings."""
        packets = [
            _make_packet(i, proto="TCP", src="10.0.0.1", dst="8.8.8.8",
                         dport=443, size=1400, payload=1350)
            for i in range(5)
        ]
        from flows.tracker import FlowTracker
        tracker = FlowTracker()
        for p in packets:
            tracker.update(p)
        findings = self._make_session(packets, tracker.get_all_flows())
        # 5 packets should not trigger any high-severity findings
        high_findings = [f for f in findings
                         if f["severity"] in ("CRITICAL", "HIGH")]
        self.assertEqual(len(high_findings), 0)

    def test_all_findings_have_evidence(self):
        """Every finding must include evidence."""
        packets = [
            _make_packet(i, proto="DNS", is_dns=True, dns_q=f"d{i}.test")
            for i in range(120)
        ]
        from flows.tracker import FlowTracker
        tracker = FlowTracker()
        for p in packets:
            tracker.update(p)
        findings = self._make_session(packets, tracker.get_all_flows())
        for f in findings:
            self.assertIn("evidence", f)
            self.assertIn("severity", f)
            self.assertIn("title", f)
            self.assertIn("recommendation", f)


# ─── 6. Statistics ────────────────────────────────────────────────────────────

class TestStatistics(unittest.TestCase):

    def _make_mixed_packets(self):
        return [
            _make_packet(1, proto="TCP", dport=443),
            _make_packet(2, proto="TCP", dport=443),
            _make_packet(3, proto="UDP", dport=53),
            _make_packet(4, proto="DNS", dport=53, is_dns=True),
            _make_packet(5, proto="ICMP", dport=0),
        ]

    def test_protocol_distribution(self):
        from analysis.statistics import calculate_protocol_distribution
        packets = self._make_mixed_packets()
        dist = calculate_protocol_distribution(packets)
        protocols = [d["protocol"] for d in dist]
        self.assertIn("TCP", protocols)
        total_count = sum(d["count"] for d in dist)
        self.assertEqual(total_count, len(packets))

    def test_direction_distribution(self):
        from analysis.statistics import calculate_direction_distribution
        packets = [
            _make_packet(1, direction="OUTGOING"),
            _make_packet(2, direction="INCOMING"),
            _make_packet(3, direction="OUTGOING"),
        ]
        dd = calculate_direction_distribution(packets)
        self.assertEqual(dd["OUTGOING"], 2)
        self.assertEqual(dd["INCOMING"], 1)

    def test_top_ips(self):
        from analysis.statistics import calculate_top_ips
        packets = [
            _make_packet(i, src="10.0.0.1", dst="8.8.8.8") for i in range(5)
        ] + [
            _make_packet(i+5, src="10.0.0.2", dst="1.1.1.1") for i in range(2)
        ]
        result = calculate_top_ips(packets)
        # Top source should be 10.0.0.1 with 5 packets
        top_src = result["top_sources"][0]
        self.assertEqual(top_src["ip"], "10.0.0.1")
        self.assertEqual(top_src["count"], 5)

    def test_payload_statistics(self):
        from analysis.statistics import calculate_payload_statistics
        packets = [
            _make_packet(1, payload=100),
            _make_packet(2, payload=200),
            _make_packet(3, payload=0),
        ]
        ps = calculate_payload_statistics(packets)
        self.assertEqual(ps["total_payload_bytes"], 300)
        self.assertEqual(ps["packets_with_payload"], 2)
        self.assertEqual(ps["packets_without_payload"], 1)
        self.assertEqual(ps["largest_payload"], 200)


# ─── 7. Timeline ──────────────────────────────────────────────────────────────

class TestTimeline(unittest.TestCase):

    def test_dns_events_generated(self):
        from investigation.timeline import build_timeline_events
        packets = [
            _make_packet(1, proto="DNS", is_dns=True, dns_q="example.com"),
            _make_packet(2, proto="DNS", is_dns=True, dns_q="google.com"),
        ]
        events = build_timeline_events(packets)
        dns_events = [e for e in events if e["event_type"] == "DNS"]
        self.assertGreater(len(dns_events), 0)

    def test_tcp_events_generated(self):
        from investigation.timeline import build_timeline_events
        packets = [_make_packet(1, proto="TCP", dport=443)]
        events = build_timeline_events(packets)
        tcp_events = [e for e in events if e["event_type"] in ("TCP", "TLS")]
        self.assertGreater(len(tcp_events), 0)

    def test_events_sorted_by_time(self):
        from investigation.timeline import build_timeline_events
        packets = [_make_packet(i) for i in range(10)]
        events = build_timeline_events(packets)
        if len(events) > 1:
            times = [e["time"] for e in events]
            self.assertEqual(times, sorted(times))

    def test_filter_by_type(self):
        from investigation.timeline import build_timeline_events, filter_events
        packets = [
            _make_packet(1, proto="DNS", is_dns=True, dns_q="a.com"),
            _make_packet(2, proto="TCP", dport=443),
        ]
        events = build_timeline_events(packets)
        dns_only = filter_events(events, "DNS")
        for e in dns_only:
            self.assertEqual(e["event_type"], "DNS")


# ─── 8. Database ─────────────────────────────────────────────────────────────

class TestDatabase(unittest.TestCase):

    def setUp(self):
        """Use an in-memory SQLite database for testing."""
        import sqlite3
        import evidence.database as db
        # Redirect to temp file for this test
        self._orig_path = db.DB_PATH
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db.DB_PATH = pathlib.Path(self._tmp.name)
        db.initialise_database()

    def tearDown(self):
        import evidence.database as db
        db.DB_PATH = self._orig_path
        pathlib.Path(self._tmp.name).unlink(missing_ok=True)

    def test_create_and_get_session(self):
        from evidence.database import create_session, get_session
        create_session("TEST-001", interface="eth0", analyst="Tester")
        s = get_session("TEST-001")
        self.assertIsNotNone(s)
        self.assertEqual(s["interface"], "eth0")
        self.assertEqual(s["analyst"], "Tester")

    def test_insert_and_retrieve_packets(self):
        from evidence.database import create_session, insert_packets_bulk, get_packets
        create_session("TEST-002")
        packets = [
            {**_make_packet(i), "session_id": "TEST-002"}
            for i in range(10)
        ]
        insert_packets_bulk("TEST-002", packets)
        retrieved = get_packets("TEST-002")
        self.assertEqual(len(retrieved), 10)

    def test_insert_and_get_alert(self):
        from evidence.database import create_session, insert_alert, get_alerts
        create_session("TEST-003")
        insert_alert("TEST-003", {
            "severity": "HIGH", "title": "Test Alert",
            "description": "desc", "evidence": "ev",
            "recommendation": "rec", "related_ip": None, "related_flow": None,
        })
        alerts = get_alerts("TEST-003")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Test Alert")

    def test_global_search(self):
        from evidence.database import create_session, insert_packets_bulk, global_search
        create_session("TEST-004")
        packets = [
            {**_make_packet(i, src="192.168.99.1"), "session_id": "TEST-004"}
            for i in range(5)
        ]
        insert_packets_bulk("TEST-004", packets)
        results = global_search("TEST-004", "192.168.99.1")
        self.assertGreater(len(results["packets"]), 0)

    def test_delete_session(self):
        from evidence.database import create_session, delete_session, get_session
        create_session("TEST-005")
        delete_session("TEST-005")
        self.assertIsNone(get_session("TEST-005"))

    def test_action_log(self):
        from evidence.database import create_session, log_action, get_action_log
        create_session("TEST-006")
        log_action("TEST-006", "CAPTURE_STARTED", "interface=eth0")
        log_action("TEST-006", "FINDING_CONFIRMED", "id=1")
        log = get_action_log("TEST-006")
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0]["action"], "CAPTURE_STARTED")

    def test_finding_state_update(self):
        from evidence.database import (
            create_session, get_connection, update_finding_state, get_findings
        )
        create_session("TEST-007")
        conn = get_connection()
        import datetime
        conn.execute(
            "INSERT INTO findings (session_id, created_at, severity, title) VALUES (?,?,?,?)",
            ("TEST-007", datetime.datetime.now().isoformat(), "MEDIUM", "Test Finding")
        )
        conn.commit()
        conn.close()

        findings = get_findings("TEST-007")
        fid = findings[0]["id"]
        update_finding_state(fid, "CONFIRMED", "Verified in logs")
        updated = get_findings("TEST-007")
        self.assertEqual(updated[0]["state"], "CONFIRMED")
        self.assertEqual(updated[0]["analyst_note"], "Verified in logs")


# ─── 9. Hashing / evidence integrity ─────────────────────────────────────────

class TestHashing(unittest.TestCase):

    def test_hash_bytes_length(self):
        from evidence.hashing import hash_bytes
        h = hash_bytes(b"test data")
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_hash_bytes_deterministic(self):
        from evidence.hashing import hash_bytes
        data = b"consistent data"
        self.assertEqual(hash_bytes(data), hash_bytes(data))

    def test_hash_file(self):
        from evidence.hashing import hash_file, verify_file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"payload capture suite test file")
            tmp = f.name
        h = hash_file(tmp)
        self.assertEqual(len(h), 64)
        self.assertTrue(verify_file(tmp, h))
        self.assertFalse(verify_file(tmp, "a" * 64))
        pathlib.Path(tmp).unlink()

    def test_format_hash_display(self):
        from evidence.hashing import format_hash_display
        h = "a" * 64
        display = format_hash_display(h)
        parts = display.split(" ")
        self.assertEqual(len(parts), 8)
        self.assertTrue(all(len(p) == 8 for p in parts))


# ─── 10. Filter translation ───────────────────────────────────────────────────

class TestFilterTranslation(unittest.TestCase):

    def test_protocol_shortcuts(self):
        from capture.filters import translate_filter
        self.assertEqual(translate_filter("TCP"),   "tcp")
        self.assertEqual(translate_filter("UDP"),   "udp")
        self.assertEqual(translate_filter("ICMP"),  "icmp")
        self.assertEqual(translate_filter("DNS"),   "udp port 53")
        self.assertEqual(translate_filter("HTTP"),  "tcp port 80")
        self.assertEqual(translate_filter("HTTPS"), "tcp port 443")

    def test_port_number(self):
        from capture.filters import translate_filter
        self.assertEqual(translate_filter("443"),  "port 443")
        self.assertEqual(translate_filter("8080"), "port 8080")

    def test_ip_address(self):
        from capture.filters import translate_filter
        self.assertEqual(translate_filter("192.168.1.1"), "host 192.168.1.1")

    def test_empty_filter(self):
        from capture.filters import translate_filter
        self.assertEqual(translate_filter(""), "")
        self.assertEqual(translate_filter("   "), "")

    def test_passthrough_bpf(self):
        from capture.filters import translate_filter
        # Raw BPF passed through unchanged
        bpf = "tcp and host 10.0.0.1 and port 80"
        self.assertEqual(translate_filter(bpf), bpf)


# ─── 11. Session state object ─────────────────────────────────────────────────

class TestInvestigationSession(unittest.TestCase):

    def setUp(self):
        """Point the database at a temp file."""
        import evidence.database as db
        self._orig = db.DB_PATH
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db.DB_PATH = pathlib.Path(self._tmp.name)
        db.initialise_database()

    def tearDown(self):
        import evidence.database as db
        db.DB_PATH = self._orig
        pathlib.Path(self._tmp.name).unlink(missing_ok=True)

    def test_create_session(self):
        from core.session import InvestigationSession, SessionStatus
        s = InvestigationSession.create(interface="eth0", analyst="TestAnalyst")
        self.assertIsNotNone(s.session_id)
        self.assertEqual(s.status, SessionStatus.CREATED)
        self.assertEqual(s.interface, "eth0")

    def test_counter_updates(self):
        from core.session import InvestigationSession
        s = InvestigationSession.create()
        s.on_packet(1400, 1350)
        s.on_packet(800, 750)
        self.assertEqual(s.packet_count, 2)
        self.assertEqual(s.byte_count, 2200)
        self.assertEqual(s.payload_bytes, 2100)

    def test_lifecycle_transitions(self):
        from core.session import InvestigationSession, SessionStatus
        s = InvestigationSession.create()
        s.start_capture()
        self.assertEqual(s.status, SessionStatus.CAPTURING)
        s.pause_capture()
        self.assertEqual(s.status, SessionStatus.PAUSED)
        s.resume_capture()
        self.assertEqual(s.status, SessionStatus.CAPTURING)
        s.stop_capture()
        self.assertEqual(s.status, SessionStatus.STOPPED)

    def test_load_session(self):
        from core.session import InvestigationSession
        s = InvestigationSession.create(interface="lo", analyst="Bob")
        sid = s.session_id

        loaded = InvestigationSession.load(sid)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.session_id, sid)
        self.assertEqual(loaded.interface, "lo")

    def test_subscriber_callback(self):
        from core.session import InvestigationSession
        s = InvestigationSession.create()
        received = []
        s.subscribe(lambda sess: received.append(sess.packet_count))
        s.on_packet(100, 50)
        s.notify_subscribers()
        self.assertEqual(received, [1])

    def test_source_label(self):
        from core.session import InvestigationSession, CaptureSource
        live = InvestigationSession.create(capture_source=CaptureSource.LIVE)
        pcap = InvestigationSession.create(capture_source=CaptureSource.PCAP)
        self.assertEqual(live.source_label, "LIVE CAPTURE")
        self.assertEqual(pcap.source_label, "PCAP ANALYSIS")


# ─── 12. Report generation ────────────────────────────────────────────────────

class TestReportGeneration(unittest.TestCase):

    def setUp(self):
        import evidence.database as db
        self._orig = db.DB_PATH
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db.DB_PATH = pathlib.Path(self._tmp.name)
        db.initialise_database()
        from evidence.database import create_session
        create_session("RPT-001", interface="eth0", analyst="Reporter")

    def tearDown(self):
        import evidence.database as db
        db.DB_PATH = self._orig
        pathlib.Path(self._tmp.name).unlink(missing_ok=True)

    def _make_test_data(self):
        packets = [_make_packet(i) for i in range(20)]
        from flows.tracker import FlowTracker
        tracker = FlowTracker()
        for p in packets:
            tracker.update(p)
        return packets, tracker.get_all_flows()

    def test_report_data_structure(self):
        from reports.report_builder import build_report_data, ALL_SECTIONS
        packets, flows = self._make_test_data()
        sections = {k: True for k in ALL_SECTIONS}
        data = build_report_data("RPT-001", sections, "Reporter", packets, flows)
        self.assertEqual(data["meta"]["analyst"], "Reporter")
        self.assertEqual(data["summary_counts"]["total_packets"], 20)
        self.assertIn("traffic", data)
        self.assertIn("findings", data)

    def test_html_report_output(self):
        from reports.report_builder import build_report_data, ALL_SECTIONS
        from reports.html_report import generate_html_report
        packets, flows = self._make_test_data()
        sections = {k: True for k in ALL_SECTIONS}
        data = build_report_data("RPT-001", sections, "Reporter", packets, flows)

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            tmp = f.name

        out = generate_html_report(data, tmp)
        content = pathlib.Path(out).read_text(encoding="utf-8")
        self.assertIn("PAYLOAD CAPTURE SUITE", content)
        self.assertIn("Reporter", content)
        self.assertGreater(len(content), 5000)
        pathlib.Path(tmp).unlink()

    def test_json_export(self):
        from reports.report_builder import build_report_data, ALL_SECTIONS
        from reports.json_report import generate_json_export
        packets, flows = self._make_test_data()
        sections = {k: True for k in ALL_SECTIONS}
        data = build_report_data("RPT-001", sections, "Reporter", packets, flows)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp = f.name

        out = generate_json_export(data, tmp)
        parsed = json.loads(pathlib.Path(out).read_text(encoding="utf-8"))
        self.assertEqual(parsed["meta"]["analyst"], "Reporter")
        pathlib.Path(tmp).unlink()

    def test_csv_export_contains_files(self):
        import zipfile
        from reports.report_builder import build_report_data, ALL_SECTIONS
        from reports.csv_report import generate_csv_export
        packets, flows = self._make_test_data()
        sections = {k: True for k in ALL_SECTIONS}
        data = build_report_data("RPT-001", sections, "Reporter", packets, flows)

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            tmp = f.name

        out = generate_csv_export(data, tmp)
        with zipfile.ZipFile(out) as zf:
            names = zf.namelist()
        self.assertIn("flows.csv", names)
        self.assertIn("findings.csv", names)
        pathlib.Path(tmp).unlink()


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Run without pytest
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(sys.modules[__name__])
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
