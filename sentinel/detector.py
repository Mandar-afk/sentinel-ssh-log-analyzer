"""Rule-based indicators for suspicious SSH authentication activity."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .parser import Event


@dataclass(frozen=True)
class Thresholds:
    failures: int = 5
    usernames: int = 5
    sources: int = 5
    window_minutes: int = 10

    def validate(self):
        for name in ("failures", "usernames", "sources", "window_minutes"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name.replace('_', ' ')} must be at least 1")


def _evidence(events: Iterable[Event]):
    return [{"time": e.timestamp.isoformat(), "source_ip": e.source_ip,
             "username": e.username, "outcome": e.outcome,
             "event_type": e.event_type, "line": e.line_number} for e in events]


def detect(events: Iterable[Event], thresholds: Thresholds = Thresholds()):
    """Return alerts with supporting event evidence. Counts are distinct events."""
    thresholds.validate()
    ordered = sorted(events, key=lambda e: (e.timestamp, e.line_number))
    alerts = []
    window = timedelta(minutes=thresholds.window_minutes)
    failures_by_ip = defaultdict(list)
    failures_by_user = defaultdict(list)
    successes_by_ip = defaultdict(list)
    ip_users, user_ips = defaultdict(list), defaultdict(list)
    for event in ordered:
        ip_users[event.source_ip].append(event)
        user_ips[event.username].append(event)
        if event.outcome == "failure":
            failures_by_ip[event.source_ip].append(event)
            failures_by_user[event.username].append(event)
        else:
            successes_by_ip[event.source_ip].append(event)

    for ip, failures in failures_by_ip.items():
        # Sliding windows, anchored at each event; emit once per source using the strongest window.
        best = []
        left = 0
        for right, event in enumerate(failures):
            while event.timestamp - failures[left].timestamp > window:
                left += 1
            candidate = failures[left:right + 1]
            if len(candidate) > len(best):
                best = candidate
        if len(best) >= thresholds.failures:
            alerts.append({"type": "repeated_failures", "severity": "high", "source_ip": ip,
                           "count": len(best), "window_minutes": thresholds.window_minutes,
                           "summary": f"{len(best)} failed authentication events from {ip} within {thresholds.window_minutes} minutes",
                           "evidence": _evidence(best)})
        for success in successes_by_ip.get(ip, []):
            success_key = (success.timestamp, success.line_number)
            prior = [f for f in failures
                     if (f.timestamp, f.line_number) < success_key and success.timestamp - f.timestamp <= window]
            if len(prior) >= thresholds.failures:
                alerts.append({"type": "success_after_failures", "severity": "high", "source_ip": ip,
                               "username": success.username, "count": len(prior), "window_minutes": thresholds.window_minutes,
                               "summary": f"Successful authentication from {ip} followed {len(prior)} failures within {thresholds.window_minutes} minutes",
                               "evidence": _evidence(prior + [success])})
                break

    for ip, activity in ip_users.items():
        usernames = sorted({e.username for e in activity})
        if len(usernames) >= thresholds.usernames:
            alerts.append({"type": "multiple_usernames", "severity": "medium", "source_ip": ip,
                           "count": len(usernames), "usernames": usernames,
                           "summary": f"Source {ip} attempted {len(usernames)} distinct usernames",
                           "evidence": _evidence(activity)})
    for username, activity in user_ips.items():
        sources = sorted({e.source_ip for e in activity})
        if len(sources) >= thresholds.sources:
            alerts.append({"type": "multiple_sources", "severity": "medium", "username": username,
                           "count": len(sources), "source_ips": sources,
                           "summary": f"Username {username} was targeted from {len(sources)} distinct sources",
                           "evidence": _evidence(activity)})
    return sorted(alerts, key=lambda a: (a["type"], a.get("source_ip", a.get("username", ""))))
