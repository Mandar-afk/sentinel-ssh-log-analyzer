"""Parsing for common OpenSSH syslog and ISO-timestamped auth log lines."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
from typing import Optional


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source_ip: str
    username: str
    outcome: str  # success or failure
    event_type: str
    line_number: int
    raw: str = ""
    pid: Optional[str] = None


_STAMP = re.compile(r"^(?P<stamp>(?:\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d(?::?\d\d)?)?)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d))\s+(?P<rest>.*)$")
_SYSLOG = "%b %d %H:%M:%S"
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
_SYSLOG_STAMP = re.compile(r"^(?P<month>[A-Z][a-z]{2})\s+")
# Syslog messages begin with a hostname, immediately followed by the sshd tag.
_SSH = re.compile(r"^(?:[^\s]+\s+)?sshd(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_PATTERNS = [
    (re.compile(r"^Failed password for invalid user (?P<user>\S+) from " + _IP), "failure", "failed_password_invalid_user"),
    (re.compile(r"^Failed password for (?P<user>\S+) from " + _IP), "failure", "failed_password"),
    (re.compile(r"^Failed (?:publickey|keyboard-interactive/pam) for invalid user (?P<user>\S+) from " + _IP), "failure", "failed_auth_invalid_user"),
    (re.compile(r"^Failed (?:publickey|keyboard-interactive/pam) for (?P<user>\S+) from " + _IP), "failure", "failed_auth"),
    (re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from " + _IP), "success", "accepted_auth"),
    (re.compile(r"^Accepted (?P<method>\S+) for invalid user (?P<user>\S+) from " + _IP), "success", "accepted_invalid_user"),
    (re.compile(r"^Invalid user (?P<user>\S+) from " + _IP), "failure", "invalid_user"),
]


def parse_line(line: str, line_number: int = 1, year: Optional[int] = None) -> Optional[Event]:
    """Parse a supported authentication event; return None for unrelated/malformed lines."""
    m = _STAMP.match(line.strip())
    if not m:
        return None
    stamp, rest = m.group("stamp"), m.group("rest")
    parsed = None
    if stamp[:4].isdigit():
        iso_str = stamp.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", iso_str):
            iso_str = f"{iso_str[:-2]}:{iso_str[-2:]}"
        try:
            parsed = datetime.fromisoformat(iso_str)
        except ValueError:
            return None
    else:
        try:
            parsed = datetime.strptime(f"{year or datetime.now().year} {stamp}", "%Y " + _SYSLOG)
        except ValueError:
            return None
    # Normalize every timestamp to naive UTC so mixed ISO/syslog files remain sortable.
    if parsed.tzinfo is None:
        parsed = parsed.astimezone().astimezone(timezone.utc).replace(tzinfo=None)
    else:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    ssh = _SSH.match(rest)
    if not ssh:
        return None
    message = ssh.group("msg")
    for pattern, outcome, kind in _PATTERNS:
        match = pattern.search(message)
        if match:
            username = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', match.group("user"))
            try:
                address = str(ipaddress.ip_address(match.group("ip")))
            except ValueError:
                return None
            return Event(parsed, address, username, outcome, kind, line_number,
                         "", ssh.group("pid"))
    return None


def parse_lines(lines, year: Optional[int] = None):
    """Return (events, malformed_count), excluding non-authentication lines."""
    events, malformed = [], 0
    log_year = year or datetime.now().year
    previous_syslog_month = None
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        stamp_match = _STAMP.match(line.strip())
        stamp = stamp_match.group("stamp") if stamp_match else ""
        syslog_match = _SYSLOG_STAMP.match(stamp)
        if syslog_match:
            month = datetime.strptime(syslog_match.group("month"), "%b").month
            if previous_syslog_month == 12 and month == 1:
                log_year += 1
            previous_syslog_month = month
        event = parse_line(line, number, log_year)
        if event is not None:
            events.append(event)
        elif (_STAMP.match(line.strip()) and "sshd" in line and
              re.search(r"(?:Failed|Accepted|Invalid user|authentication failure)", line, re.IGNORECASE)):
            malformed += 1
    # OpenSSH may log both notices for one invalid username attempt. Keep the
    # detailed failure record and drop the paired notice when PID is available.
    paired_failures = {
        (e.timestamp, e.pid, e.source_ip, e.username)
        for e in events
        if e.event_type in ("failed_password_invalid_user", "failed_auth_invalid_user") and e.pid is not None
    }
    events = [e for e in events if not (
        e.event_type == "invalid_user" and e.pid is not None and
        (e.timestamp, e.pid, e.source_ip, e.username) in paired_failures
    )]
    events.sort(key=lambda e: (e.timestamp, e.line_number))
    return events, malformed
