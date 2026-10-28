import json
import gzip
import io
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

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

    def test_iso_microseconds(self):
        event = parse_line("2026-10-28T09:00:00.123456Z host sshd: Failed password for joe from 192.0.2.3 port 22 ssh2")
        self.assertEqual(event.timestamp.microsecond, 123456)

    def test_iso_offset_without_colon(self):
        event = parse_line("2026-10-28T09:00:00+0000 host sshd: Failed password for joe from 192.0.2.3 port 22 ssh2")
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "joe")
        self.assertEqual(event.raw, "")

    def test_container_log_without_hostname(self):
        event = parse_line("2026-10-28T09:00:00Z sshd[123]: Failed password for root from 192.0.2.3 port 22 ssh2")
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "root")

    def test_syslog_year_rollover(self):
        events, malformed = parse_lines([
            "Dec 31 23:59:00 host sshd[10]: Failed password for joe from 192.0.2.3 port 22 ssh2",
            "Jan  1 00:01:00 host sshd[11]: Failed password for joe from 192.0.2.3 port 22 ssh2",
        ], year=2025)
        self.assertEqual(malformed, 0)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1].timestamp - events[0].timestamp, timedelta(minutes=2))

    def test_username_control_characters_are_removed(self):
        event = parse_line("Oct 28 09:00:00 host sshd[1]: Failed password for ad\x01min from 192.0.2.3 port 22 ssh2", year=2026)
        self.assertEqual(event.username, "admin")

    def test_paired_invalid_user_notice_is_deduplicated(self):
        events, malformed = parse_lines([
            "Oct 28 09:00:00 host sshd[42]: Invalid user guest from 192.0.2.3 port 22",
            "Oct 28 09:00:00 host sshd[42]: Failed password for invalid user guest from 192.0.2.3 port 22 ssh2",
        ], year=2026)
        self.assertEqual(malformed, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "failed_password_invalid_user")

    def test_paired_publickey_invalid_user_is_deduplicated(self):
        events, malformed = parse_lines([
            "Oct 28 09:00:00 host sshd[42]: Invalid user guest from 192.0.2.3 port 22",
            "Oct 28 09:00:00 host sshd[42]: Failed publickey for invalid user guest from 192.0.2.3 port 22 ssh2",
        ], year=2026)
        self.assertEqual(malformed, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "failed_auth_invalid_user")

    def test_ssh_tag_must_follow_hostname(self):
        self.assertIsNone(parse_line("Oct 28 09:00:00 host service sshd[1]: Failed password for joe from 192.0.2.3 port 22", year=2026))

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
        alerts = detect(self.events, Thresholds(failures=8, usernames=99, sources=99, window_minutes=3))
        # No five failures from this source fit into three minutes.
        self.assertNotIn("repeated_failures", {a["type"] for a in alerts})

    def test_benign_activity_does_not_trigger(self):
        one = [e for e in self.events if e.source_ip == "192.0.2.8"]
        self.assertEqual(detect(one, Thresholds()), [])

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            detect([], Thresholds(failures=0))

    def test_failure_after_success_at_same_timestamp_is_not_prior(self):
        target = next(e for e in self.events if e.source_ip == "192.0.2.8")
        success = replace(target, timestamp=target.timestamp.replace(minute=0), line_number=1)
        failure = replace(target, timestamp=success.timestamp, outcome="failure", line_number=2)
        alerts = detect([success, failure], Thresholds(failures=1))
        self.assertNotIn("success_after_failures", {alert["type"] for alert in alerts})

    def test_success_correlation_requires_matching_username_and_reports_each_success(self):
        base = next(e for e in self.events if e.source_ip == "203.0.113.10")
        failures_wave1 = [replace(base, username="deploy", outcome="failure", line_number=i,
                                  timestamp=base.timestamp + timedelta(seconds=i)) for i in range(1, 5)]
        mismatched = replace(base, username="admin", outcome="success", line_number=5,
                             timestamp=base.timestamp + timedelta(seconds=5))
        success1 = replace(base, username="deploy", outcome="success", line_number=6,
                           timestamp=base.timestamp + timedelta(seconds=6))
        failures_wave2 = [replace(base, username="deploy", outcome="failure", line_number=10 + i,
                                  timestamp=base.timestamp + timedelta(minutes=15, seconds=i)) for i in range(1, 5)]
        success2 = replace(base, username="deploy", outcome="success", line_number=20,
                           timestamp=base.timestamp + timedelta(minutes=16))

        alerts = detect(failures_wave1 + [mismatched, success1] + failures_wave2 + [success2], Thresholds(failures=4))
        success_alerts = [alert for alert in alerts if alert["type"] == "success_after_failures"]
        self.assertEqual(len(success_alerts), 2)
        self.assertTrue(all(alert["username"] == "deploy" for alert in success_alerts))

    def test_repeated_failures_rolling_window_does_not_miss_split_clusters(self):
        base = self.events[0]
        events = [replace(base, outcome="failure", line_number=1, timestamp=base.timestamp)]
        events.extend(replace(base, outcome="failure", line_number=i + 2,
                              timestamp=base.timestamp + timedelta(minutes=8 + i)) for i in range(6))
        alerts = detect(events, Thresholds(failures=5, window_minutes=10))
        repeated = [a for a in alerts if a["type"] == "repeated_failures"]
        self.assertEqual(len(repeated), 1)
        self.assertEqual(repeated[0]["count"], 6)

    def test_rapid_successes_do_not_produce_duplicate_alerts(self):
        base = self.events[0]
        failures = [replace(base, username="deploy", outcome="failure", line_number=i,
                            timestamp=base.timestamp + timedelta(seconds=i)) for i in range(5)]
        rapid_successes = [replace(base, username="deploy", outcome="success", line_number=10 + i,
                                   timestamp=base.timestamp + timedelta(seconds=30 + i * 2)) for i in range(3)]
        alerts = detect(failures + rapid_successes, Thresholds(failures=5))
        saf = [a for a in alerts if a["type"] == "success_after_failures"]
        self.assertEqual(len(saf), 1)

    def test_password_spray_success_detected(self):
        base = self.events[0]
        users = ["user1", "user2", "user3", "user4", "user5"]
        failures = [replace(base, username=u, outcome="failure", line_number=i + 1,
                            timestamp=base.timestamp + timedelta(minutes=i)) for i, u in enumerate(users)]
        success = replace(base, username="user3", outcome="success", line_number=10,
                          timestamp=base.timestamp + timedelta(minutes=6))
        alerts = detect(failures + [success], Thresholds(failures=5, usernames=5, window_minutes=10))
        spray_alerts = [a for a in alerts if a["type"] == "spray_success"]
        self.assertEqual(len(spray_alerts), 1)
        self.assertEqual(spray_alerts[0]["username"], "user3")

    def test_repeated_failure_alerts_are_non_overlapping_and_evidence_is_bounded(self):
        base = self.events[0]
        events = [replace(base, outcome="failure", line_number=i + 1,
                          timestamp=base.timestamp + timedelta(minutes=i)) for i in range(2)]
        events.extend(replace(base, outcome="failure", line_number=i + 1,
                              timestamp=base.timestamp + timedelta(minutes=20 + i)) for i in range(2))
        alerts = detect(events, Thresholds(failures=2, window_minutes=5))
        repeated = [alert for alert in alerts if alert["type"] == "repeated_failures"]
        self.assertEqual(len(repeated), 2)
        large = [replace(base, outcome="failure", line_number=i + 1,
                         timestamp=base.timestamp + timedelta(minutes=i)) for i in range(25)]
        alert = next(a for a in detect(large, Thresholds(failures=1, window_minutes=60)) if a["type"] == "repeated_failures")
        self.assertEqual(alert["total_count"], 25)
        self.assertEqual(len(alert["evidence"]), 20)
        self.assertEqual(alert["evidence"][0]["line"], 1)
        self.assertEqual(alert["evidence"][-1]["line"], 25)

    def test_diversity_rules_use_separate_rolling_windows(self):
        base = self.events[0]
        events = [
            replace(base, username="one", timestamp=base.timestamp, line_number=1),
            replace(base, username="one", timestamp=base.timestamp + timedelta(minutes=5), line_number=2),
            replace(base, username="two", timestamp=base.timestamp + timedelta(minutes=6), line_number=3),
            replace(base, username="three", timestamp=base.timestamp + timedelta(minutes=10), line_number=4),
            replace(base, username="shared", source_ip="192.0.2.10", timestamp=base.timestamp + timedelta(minutes=20), line_number=5),
            replace(base, username="shared", source_ip="192.0.2.10", timestamp=base.timestamp + timedelta(minutes=25), line_number=6),
            replace(base, username="shared", source_ip="192.0.2.11", timestamp=base.timestamp + timedelta(minutes=26), line_number=7),
            replace(base, username="shared", source_ip="192.0.2.12", timestamp=base.timestamp + timedelta(minutes=30), line_number=8),
        ]
        alerts = detect(events, Thresholds(failures=99, usernames=2, sources=2, window_minutes=5))
        by_type = {}
        for alert in alerts:
            by_type[alert["type"]] = by_type.get(alert["type"], 0) + 1
        self.assertEqual(by_type, {"multiple_sources": 1, "multiple_usernames": 1})


class CliTests(unittest.TestCase):
    def test_cli_exit_code_flag(self):
        from io import StringIO
        import contextlib
        with contextlib.redirect_stdout(StringIO()):
            ret_alert = main([str(FIXTURE), "--year", "2026", "--failures", "2", "--exit-code"])
            ret_clean = main([str(FIXTURE), "--year", "2026", "--failures", "999", "--usernames", "999", "--sources", "999", "--exit-code"])
        self.assertEqual(ret_alert, 1)
        self.assertEqual(ret_clean, 0)

    def test_cli_severity_and_rule_filters(self):
        from io import StringIO
        import contextlib
        out = StringIO()
        with contextlib.redirect_stdout(out):
            main([str(FIXTURE), "--year", "2026", "--failures", "4", "--rules", "repeated_failures", "--format", "json"])
        report = json.loads(out.getvalue())
        self.assertTrue(report["alerts"])
        self.assertTrue(all(a["type"] == "repeated_failures" for a in report["alerts"]))
        out = StringIO()
        with contextlib.redirect_stdout(out):
            main([str(FIXTURE), "--year", "2026", "--min-severity", "high", "--format", "json"])
        report = json.loads(out.getvalue())
        self.assertTrue(report["alerts"])
        self.assertTrue(all(a["severity"] == "high" for a in report["alerts"]))

    def test_gzip_input(self):
        from io import StringIO
        import contextlib
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log.gz"
            with gzip.open(path, "wt", encoding="utf-8") as compressed:
                compressed.write(FIXTURE.read_text(encoding="utf-8"))
            output = StringIO()
            with contextlib.redirect_stdout(output):
                result = main([str(path), "--format", "json", "--year", "2026"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["events_parsed"], 14)

    def test_stdin_dash_input(self):
        from io import StringIO
        import contextlib
        output = StringIO()
        with patch("sentinel.cli.sys.stdin", io.StringIO(FIXTURE.read_text(encoding="utf-8"))), contextlib.redirect_stdout(output):
            result = main(["-", "--format", "json", "--year", "2026"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["events_parsed"], 14)

    def test_json_cli(self):
        from io import StringIO
        import contextlib
        output = StringIO()
        with contextlib.redirect_stdout(output):
            result = main([str(FIXTURE), "--format", "json", "--year", "2026", "--failures", "4", "--usernames", "4", "--sources", "4"])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["events_parsed"], 14)
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
