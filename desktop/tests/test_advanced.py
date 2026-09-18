"""
tests/test_advanced.py

Tests for the advanced offline detection rules, risk scoring and the
bundled local intelligence tables.

Run with:
    python -m unittest tests.test_advanced -v
"""

import datetime
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from analysis.advanced_rules import (          # noqa: E402
    check_beaconing, check_port_scan, check_host_sweep,
    check_exfiltration_volume, check_entropy_anomaly,
    check_dns_tunnelling, check_off_hours_activity,
    run_advanced_rules, score_findings,
)
from investigation.local_intel import (        # noqa: E402
    service_for_port, classify_block, organisation_hint, describe_ip,
)

BASE = datetime.datetime(2026, 9, 18, 23, 0, 0)


def _packet(**kwargs) -> dict:
    packet = {
        "src_ip": "192.168.1.10", "dst_ip": "203.0.113.5",
        "src_port": 51000, "dst_port": 443,
        "protocol": "TCP", "direction": "OUTGOING",
        "capture_time": BASE.isoformat(), "packet_size": 100,
        "payload_size": 40,
    }
    packet.update(kwargs)
    return packet


class TestBeaconing(unittest.TestCase):
    def test_regular_interval_is_flagged(self):
        packets = [
            _packet(capture_time=(BASE + datetime.timedelta(seconds=60 * i)).isoformat())
            for i in range(12)
        ]
        findings = check_beaconing(packets, [])
        self.assertTrue(findings)
        self.assertIn("beaconing", findings[0]["title"].lower())
        self.assertGreater(findings[0]["confidence"], 50)

    def test_irregular_traffic_is_not_flagged(self):
        gaps = [0, 3, 41, 7, 190, 12, 400, 22, 61, 5]
        offset = 0
        packets = []
        for gap in gaps:
            offset += gap
            packets.append(
                _packet(capture_time=(BASE + datetime.timedelta(seconds=offset)).isoformat())
            )
        self.assertEqual(check_beaconing(packets, []), [])

    def test_too_few_events_is_not_flagged(self):
        packets = [
            _packet(capture_time=(BASE + datetime.timedelta(seconds=30 * i)).isoformat())
            for i in range(3)
        ]
        self.assertEqual(check_beaconing(packets, []), [])


class TestScanning(unittest.TestCase):
    def test_port_scan_detected(self):
        packets = [
            _packet(src_ip="10.0.0.9", dst_ip="10.0.0.20",
                    dst_port=1000 + i, direction="INTERNAL")
            for i in range(40)
        ]
        findings = check_port_scan(packets, [])
        self.assertTrue(findings)
        self.assertEqual(findings[0]["related_ip"], "10.0.0.9")

    def test_normal_browsing_is_not_a_scan(self):
        packets = [_packet(dst_port=443), _packet(dst_port=80), _packet(dst_port=53)]
        self.assertEqual(check_port_scan(packets, []), [])

    def test_host_sweep_detected(self):
        packets = [
            _packet(src_ip="10.0.0.9", dst_ip=f"10.0.0.{i}",
                    dst_port=445, direction="INTERNAL")
            for i in range(1, 40)
        ]
        self.assertTrue(check_host_sweep(packets, []))


class TestExfiltration(unittest.TestCase):
    def test_large_one_sided_upload_detected(self):
        packets = [
            _packet(direction="OUTGOING", dst_ip="203.0.113.77", packet_size=60_000)
            for _ in range(200)
        ]
        findings = check_exfiltration_volume(packets, [])
        self.assertTrue(findings)
        self.assertIn(findings[0]["severity"], ("HIGH", "CRITICAL"))

    def test_balanced_traffic_not_flagged(self):
        packets = []
        for _ in range(200):
            packets.append(_packet(direction="OUTGOING", dst_ip="203.0.113.77",
                                   packet_size=60_000))
            packets.append(_packet(direction="INCOMING", src_ip="203.0.113.77",
                                   packet_size=60_000))
        self.assertEqual(check_exfiltration_volume(packets, []), [])


class TestEntropyAndDns(unittest.TestCase):
    def test_high_entropy_on_plaintext_port(self):
        packets = [
            _packet(dst_port=80, payload_entropy=7.9, payload_size=800)
            for _ in range(5)
        ]
        self.assertTrue(check_entropy_anomaly(packets, []))

    def test_high_entropy_on_https_ignored(self):
        packets = [
            _packet(dst_port=443, payload_entropy=7.9, payload_size=800)
            for _ in range(5)
        ]
        self.assertEqual(check_entropy_anomaly(packets, []), [])

    def test_dns_tunnelling_detected(self):
        long_label = "a1b2c3d4e5" * 6
        packets = [
            _packet(dst_port=53, dns_query=f"{long_label}.tunnel-example.com")
            for _ in range(4)
        ]
        findings = check_dns_tunnelling(packets, [])
        self.assertTrue(findings)
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_normal_dns_not_flagged(self):
        packets = [_packet(dst_port=53, dns_query="www.example.com") for _ in range(20)]
        self.assertEqual(check_dns_tunnelling(packets, []), [])


class TestOffHours(unittest.TestCase):
    def test_night_activity_flagged(self):
        packets = [_packet() for _ in range(250)]
        self.assertTrue(check_off_hours_activity(packets, []))

    def test_daytime_activity_not_flagged(self):
        day = BASE.replace(hour=14)
        packets = [_packet(capture_time=day.isoformat()) for _ in range(250)]
        self.assertEqual(check_off_hours_activity(packets, []), [])


class TestRobustness(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(run_advanced_rules([], []), [])

    def test_malformed_packets_do_not_raise(self):
        junk = [{}, {"src_ip": None}, {"capture_time": "not-a-date"},
                {"dst_port": "abc", "payload_entropy": "high"}]
        self.assertIsInstance(run_advanced_rules(junk, []), list)

    def test_every_finding_has_required_keys(self):
        packets = [
            _packet(capture_time=(BASE + datetime.timedelta(seconds=60 * i)).isoformat())
            for i in range(12)
        ]
        for finding in run_advanced_rules(packets, []):
            for key in ("severity", "title", "description", "evidence",
                        "recommendation", "technique", "confidence"):
                self.assertIn(key, finding)
            self.assertTrue(finding["evidence"])


class TestScoring(unittest.TestCase):
    def test_clean_session_scores_zero(self):
        result = score_findings([])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], "CLEAN")

    def test_score_never_exceeds_100(self):
        result = score_findings([{"severity": "CRITICAL", "confidence": 100}] * 50)
        self.assertLessEqual(result["score"], 100)
        self.assertEqual(result["band"], "CRITICAL")

    def test_more_severe_scores_higher(self):
        low = score_findings([{"severity": "LOW", "confidence": 60}])["score"]
        high = score_findings([{"severity": "CRITICAL", "confidence": 90}])["score"]
        self.assertGreater(high, low)

    def test_bad_confidence_does_not_raise(self):
        self.assertIsInstance(
            score_findings([{"severity": "HIGH", "confidence": "unknown"}])["score"],
            int,
        )


class TestLocalIntel(unittest.TestCase):
    def test_known_port(self):
        info = service_for_port(445)
        self.assertEqual(info["service"], "SMB")
        self.assertEqual(info["risk"], "HIGH")

    def test_ephemeral_port(self):
        self.assertIn("Ephemeral", service_for_port(55123)["service"])

    def test_bad_port_input(self):
        self.assertEqual(service_for_port(None)["service"], "—")
        self.assertEqual(service_for_port("abc")["service"], "Unknown")

    def test_private_block(self):
        block = classify_block("192.168.4.7")
        self.assertIsNotNone(block)
        self.assertEqual(block["label"], "Private network")

    def test_organisation_hint(self):
        hint = organisation_hint("8.8.8.8")
        self.assertIsNotNone(hint)
        self.assertEqual(hint["organisation"], "Google")
        self.assertFalse(hint["authoritative"])

    def test_no_hint_for_private_ip(self):
        self.assertIsNone(organisation_hint("10.1.1.1"))

    def test_describe_invalid_ip(self):
        self.assertFalse(describe_ip("not-an-ip")["valid"])

    def test_describe_public_ip(self):
        described = describe_ip("1.1.1.1")
        self.assertTrue(described["valid"])
        self.assertEqual(described["scope"], "Public")
        self.assertIn("Cloudflare", described["summary"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
