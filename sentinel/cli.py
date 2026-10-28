"""Command-line interface for Sentinel."""
import argparse
from contextlib import nullcontext
import gzip
import sys

from .detector import Thresholds, detect
from .parser import parse_lines
from .report import make_report, render_json, render_terminal


def build_parser():
    parser = argparse.ArgumentParser(prog="sentinel", description="Analyze Linux SSH authentication logs")
    parser.add_argument("logfile", help="path to an auth.log or secure log")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="report format")
    parser.add_argument("--failures", type=int, default=5, help="failed events to flag (default: 5)")
    parser.add_argument("--usernames", type=int, default=5, help="distinct usernames per source (default: 5)")
    parser.add_argument("--sources", type=int, default=5, help="distinct sources per username (default: 5)")
    parser.add_argument("--window", type=int, default=10, help="detection window in minutes (default: 10)")
    parser.add_argument("--year", type=int, default=None, help="year for traditional syslog timestamps; defaults to current year")
    parser.add_argument("--exit-code", action="store_true", help="exit with status 1 if any alerts are detected")
    parser.add_argument("--min-severity", choices=("low", "medium", "high"), default=None, help="minimum alert severity to report")
    parser.add_argument("--rules", default=None, help="comma-separated alert types to include (e.g. repeated_failures,spray_success)")
    return parser


def open_log(source):
    """Open a regular/gzip log, or return stdin without taking ownership."""
    if source == "-":
        return nullcontext(sys.stdin)
    if source is sys.stdin:
        return nullcontext(source)
    if str(source).endswith(".gz"):
        return gzip.open(source, "rt", encoding="utf-8", errors="replace")
    return open(source, encoding="utf-8", errors="replace")


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        thresholds = Thresholds(args.failures, args.usernames, args.sources, args.window)
        thresholds.validate()
        if args.year is not None and not 1970 <= args.year <= 9998:
            raise ValueError("year must be between 1970 and 9998")
        with open_log(args.logfile) as log:
            events, malformed = parse_lines(log, args.year)
    except (OSError, ValueError) as exc:
        print(f"sentinel: {exc}", file=sys.stderr)
        return 2
    alerts = detect(events, thresholds)
    if args.min_severity:
        severity_rank = {"low": 1, "medium": 2, "high": 3}
        min_rank = severity_rank.get(args.min_severity.lower(), 1)
        alerts = [a for a in alerts if severity_rank.get(a.get("severity", "low").lower(), 1) >= min_rank]
    if args.rules:
        allowed_rules = {r.strip() for r in args.rules.split(",") if r.strip()}
        alerts = [a for a in alerts if a.get("type") in allowed_rules]

    report = make_report(events, alerts, malformed, args.logfile)
    print(render_json(report) if args.format == "json" else render_terminal(report))
    if args.exit_code and len(report["alerts"]) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
