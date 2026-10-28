import json
from pathlib import Path
import tempfile
import unittest

from sentinel.cli import main
from sentinel.detector import Thresholds, detect
from sentinel.parser import parse_line, parse_lines


FIXTURE = Path(__file__).parent / "data" / "auth.log"


class ParserTests(unittest.TestCase):
    def test_supported_syslog_event_and_ipv6(self):
        event = parse_line("Oct 28 09:00:00 host sshd[1]: Accepted publickey for maya from 2001:db8::1 port 22 ssh2", year=2026)
        self.assertEqual((event.username, event.source_ip, event.outcome), ("maya", "2001:db8::1", "success"))
        self.assertEqual(event.timestamp.year, 2026)

    def test_iso_timestamp(self):
        event = parse_line("2026-10-28T09:00:00Z host sshd: Failed password for joe from 192.0.2.3 port 22 ssh2")
        self.assertIsNone(event.timestamp.utcoffset())  # parser stores normalized naive UTC

    def test_mixed_timestamp_formats_are_orderable(self):
        events, malformed = parse_lines([
            "Oct 28 09:00:00 host sshd: Failed password for x from 192.0.2.2 port 22 ssh2",
            "2026-10-28T09:01:00Z host sshd: Failed password for x from 192.0.2.2 port 22 ssh2",
        ], year=2026)
        self.assertEqual(malformed, 0)
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event.timestamp.utcoffset() is None for event in events))

    def test_malformed_and_non_auth_lines_are_skipped(self):
        events, malformed = parse_lines(["", "not a log", "Oct 28 09:00:00 host sshd: Failed password for x from nope port 2"] , year=2026)
        self.assertEqual(events, [])
        self.assertEqual(malformed, 1)


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with FIXTURE.open() as log:
            cls.events, cls.malformed = parse_lines(log, year=2026)

    def test_required_indicators_and_evidence(self):
        alerts = detect(self.events, Thresholds(failures=4, usernames=3, sources=4, window_minutes=10))
        kinds = {a["type"] for a in alerts}
        self.assertTrue({"repeated_failures", "success_after_failures", "multiple_usernames", "multiple_sources"} <= kinds)
        for alert in alerts:
            self.assertTrue(alert["evidence"])
            self.assertTrue(all("line" in evidence and "source_ip" in evidence for evidence in alert["evidence"]))

    def test_threshold_boundary_and_outside_window(self):
        alerts = detect(self.events, Thresholds(failures=5, usernames=99, sources=99, window_minutes=3))
        # No five failures from this source fit into three minutes.
        self.assertNotIn("repeated_failures", {a["type"] for a in alerts})

    def test_benign_activity_does_not_trigger(self):
        one = [e for e in self.events if e.source_ip == "192.0.2.8"]
        self.assertEqual(detect(one, Thresholds()), [])

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            detect([], Thresholds(failures=0))

    def test_failure_after_success_at_same_timestamp_is_not_prior(self):
        from dataclasses import replace
        target = next(e for e in self.events if e.source_ip == "192.0.2.8")
        success = replace(target, timestamp=target.timestamp.replace(minute=0), line_number=1)
        failure = replace(target, timestamp=success.timestamp, outcome="failure", line_number=2)
        alerts = detect([success, failure], Thresholds(failures=1))
        self.assertNotIn("success_after_failures", {alert["type"] for alert in alerts})


class CliTests(unittest.TestCase):
    def test_json_cli(self):
        from io import StringIO
        import contextlib
        output = StringIO()
        with contextlib.redirect_stdout(output):
            result = main([str(FIXTURE), "--format", "json", "--year", "2026", "--failures", "4", "--usernames", "4", "--sources", "4"])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["events_parsed"], 11)
        self.assertEqual(report["malformed_lines"], 1)

    def test_missing_file_is_graceful(self):
        from io import StringIO
        import contextlib
        error = StringIO()
        with contextlib.redirect_stderr(error):
            result = main([str(FIXTURE.parent / "missing.log")])
        self.assertEqual(result, 2)
        self.assertIn("sentinel:", error.getvalue())


if __name__ == "__main__":
    unittest.main()
