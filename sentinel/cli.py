"""Command-line interface for Sentinel."""
import argparse
from datetime import datetime
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
    parser.add_argument("--window", type=int, default=10, help="failure window in minutes (default: 10)")
    parser.add_argument("--year", type=int, default=None, help="year for traditional syslog timestamps; defaults to current year")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        thresholds = Thresholds(args.failures, args.usernames, args.sources, args.window)
        thresholds.validate()
        if args.year is not None and not 1970 <= args.year <= 9998:
            raise ValueError("year must be between 1970 and 9998")
        with open(args.logfile, encoding="utf-8", errors="replace") as log:
            events, malformed = parse_lines(log, args.year)
    except (OSError, ValueError) as exc:
        print(f"sentinel: {exc}", file=sys.stderr)
        return 2
    report = make_report(events, detect(events, thresholds), malformed, args.logfile)
    print(render_json(report) if args.format == "json" else render_terminal(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
