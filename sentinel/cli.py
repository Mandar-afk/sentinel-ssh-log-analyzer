"""Command-line interface for Sentinel."""
import argparse
from contextlib import nullcontext
import gzip
import http.server
import sys

from .detector import Thresholds, detect
from .parser import parse_lines
from .report import make_report, render_html, render_json, render_terminal


def build_parser():
    parser = argparse.ArgumentParser(prog="sentinel", description="Analyze Linux SSH authentication logs")
    parser.add_argument("logfile", help="path to an auth.log or secure log")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text", help="report format")
    parser.add_argument("--serve", nargs="?", const=8080, type=int, default=None, metavar="PORT",
                        help="start local web server to view report (default port: 8080)")
    parser.add_argument("--cidr-v4", type=int, default=None, metavar="PREFIX",
                        help="aggregate IPv4 sources by CIDR prefix (e.g. 24)")
    parser.add_argument("--cidr-v6", type=int, default=None, metavar="PREFIX",
                        help="aggregate IPv6 sources by CIDR prefix (e.g. 64)")
    parser.add_argument("--failures", type=int, default=5, help="failed events to flag (default: 5)")
    parser.add_argument("--usernames", type=int, default=5, help="distinct usernames per source (default: 5)")
    parser.add_argument("--sources", type=int, default=5, help="distinct sources per username (default: 5)")
    parser.add_argument("--window", type=int, default=10, help="detection window in minutes (default: 10)")
    parser.add_argument("--year", type=int, default=None, help="year for traditional syslog timestamps; defaults to current year")
    parser.add_argument("--exit-code", action="store_true", help="exit with status 1 if any alerts are detected")
    parser.add_argument("--min-severity", choices=("low", "medium", "high"), default=None, help="minimum alert severity to report")
    parser.add_argument("--rules", default=None, help="comma-separated alert types to include (e.g. repeated_failures,spray_success)")
    return parser


class _SentinelReportHandler(http.server.BaseHTTPRequestHandler):
    html_content = b""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.html_content)))
        self.end_headers()
        self.wfile.write(self.html_content)

    def log_message(self, format, *args):
        # Quiet standard request access logs.
        pass


def serve_report(html_text: str, port: int = 8080):
    """Serve the interactive HTML report on 127.0.0.1 until terminated."""
    handler = _SentinelReportHandler
    handler.html_content = html_text.encode("utf-8")
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    print(f"Sentinel Interactive Report running at http://127.0.0.1:{port}/")
    print("Serving locally. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Sentinel web server.")
    finally:
        server.server_close()


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
        thresholds = Thresholds(args.failures, args.usernames, args.sources, args.window,
                                cidr_ipv4=args.cidr_v4, cidr_ipv6=args.cidr_v6)
        thresholds.validate()
        if args.serve is not None and not 1 <= args.serve <= 65535:
            raise ValueError("serve port must be between 1 and 65535")
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
    if args.serve is not None:
        try:
            serve_report(render_html(report), port=args.serve)
        except OSError as exc:
            print(f"sentinel: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.format == "json":
        print(render_json(report))
    elif args.format == "html":
        print(render_html(report))
    else:
        print(render_terminal(report))
    if args.exit_code and len(report["alerts"]) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
