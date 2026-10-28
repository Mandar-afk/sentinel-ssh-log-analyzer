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
    raw: str


_STAMP = re.compile(r"^(?P<stamp>(?:\d{4}-\d\d-\d\d[T ][^ ]+)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d))\s+(?P<rest>.*)$")
_SYSLOG = "%b %d %H:%M:%S"
_ISO = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
_SSH = re.compile(r"sshd(?:\[\d+\])?:\s*(?P<msg>.*)$")
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
    for fmt in _ISO:
        try:
            parsed = datetime.strptime(stamp, fmt)
            break
        except ValueError:
            pass
    if parsed is None:
        try:
            parsed = datetime.strptime(f"{year or datetime.now().year} {stamp}", "%Y " + _SYSLOG)
        except ValueError:
            return None
    # Normalize every timestamp to naive UTC so mixed ISO/syslog files remain sortable.
    if parsed.tzinfo is None:
        parsed = parsed.astimezone().astimezone(timezone.utc).replace(tzinfo=None)
    else:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    ssh = _SSH.search(rest)
    if not ssh:
        return None
    message = ssh.group("msg")
    for pattern, outcome, kind in _PATTERNS:
        match = pattern.search(message)
        if match:
            username = match.group("user")
            try:
                address = str(ipaddress.ip_address(match.group("ip")))
            except ValueError:
                return None
            return Event(parsed, address, username, outcome, kind, line_number, line.rstrip("\n"))
    return None


def parse_lines(lines, year: Optional[int] = None):
    """Return (events, malformed_count), excluding non-authentication lines."""
    events, malformed = [], 0
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        event = parse_line(line, number, year)
        if event is not None:
            events.append(event)
        elif (_STAMP.match(line.strip()) and "sshd" in line and
              re.search(r"(?:Failed|Accepted|Invalid user|authentication failure)", line, re.IGNORECASE)):
            malformed += 1
    events.sort(key=lambda e: (e.timestamp, e.line_number))
    return events, malformed
