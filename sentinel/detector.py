"""Rule-based indicators for suspicious SSH authentication activity."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
import ipaddress
from typing import Iterable, Optional

from .parser import Event


@dataclass(frozen=True)
class Thresholds:
    failures: int = 5
    usernames: int = 5
    sources: int = 5
    window_minutes: int = 10
    cidr_ipv4: Optional[int] = None
    cidr_ipv6: Optional[int] = None

    def validate(self):
        for name in ("failures", "usernames", "sources", "window_minutes"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name.replace('_', ' ')} must be at least 1")
        if self.cidr_ipv4 is not None and not (1 <= self.cidr_ipv4 <= 32):
            raise ValueError("cidr ipv4 prefix must be between 1 and 32")
        if self.cidr_ipv6 is not None and not (1 <= self.cidr_ipv6 <= 128):
            raise ValueError("cidr ipv6 prefix must be between 1 and 128")


def _network_key(ip_str: str, cidr_v4: Optional[int], cidr_v6: Optional[int]) -> str:
    """Return the CIDR subnet string if prefix is configured, else original IP."""
    if cidr_v4 is None and cidr_v6 is None:
        return ip_str
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4 and cidr_v4 is not None:
            return str(ipaddress.ip_network(f"{ip_str}/{cidr_v4}", strict=False))
        if ip.version == 6 and cidr_v6 is not None:
            return str(ipaddress.ip_network(f"{ip_str}/{cidr_v6}", strict=False))
    except ValueError:
        pass
    return ip_str


def _evidence(events: Iterable[Event]):
    samples = list(events)
    evidence = [{"time": e.timestamp.isoformat(), "source_ip": e.source_ip,
             "username": e.username, "outcome": e.outcome,
             "event_type": e.event_type, "line": e.line_number} for e in samples]
    if len(evidence) > 20:
        evidence = evidence[:10] + evidence[-10:]
    return evidence, len(samples)


def _alert_evidence(alert, events):
    alert["evidence"], alert["total_count"] = _evidence(events)
    return alert


def _qualifying_rolling_windows(events, window, predicate):
    """Yield qualifying rolling windows, advancing past each emitted window."""
    start = 0
    while start < len(events):
        end = start + 1
        while end < len(events) and events[end].timestamp - events[start].timestamp <= window:
            end += 1
        candidate = events[start:end]
        if predicate(candidate):
            yield candidate
            start = end
        else:
            start += 1


def detect(events: Iterable[Event], thresholds: Thresholds = Thresholds()):
    """Return alerts with supporting event evidence. Counts are distinct events."""
    thresholds.validate()
    ordered = sorted(events, key=lambda e: (e.timestamp, e.line_number))
    alerts = []
    window = timedelta(minutes=thresholds.window_minutes)
    failures_by_ip = defaultdict(list)
    failures_by_ip_user = defaultdict(list)
    successes_by_ip = defaultdict(list)
    successes_by_ip_user = defaultdict(list)
    ip_users, user_ips = defaultdict(list), defaultdict(list)
    for event in ordered:
        source_key = _network_key(event.source_ip, thresholds.cidr_ipv4, thresholds.cidr_ipv6)
        ip_users[source_key].append(event)
        user_ips[event.username].append(event)
        if event.outcome == "failure":
            failures_by_ip[source_key].append(event)
            failures_by_ip_user[(source_key, event.username)].append(event)
        else:
            successes_by_ip[source_key].append(event)
            successes_by_ip_user[(source_key, event.username)].append(event)

    # 1. Repeated failures: use qualifying rolling window to avoid tumbling window splits
    for ip, failures in failures_by_ip.items():
        for failure_window in _qualifying_rolling_windows(
                failures, window, lambda batch: len(batch) >= thresholds.failures):
            alert = {"type": "repeated_failures", "severity": "high", "source_ip": ip,
                     "count": len(failure_window), "window_minutes": thresholds.window_minutes,
                     "summary": f"{len(failure_window)} failed authentication events from {ip} within {thresholds.window_minutes} minutes",
                     "window_start": failure_window[0].timestamp.isoformat(),
                     "window_end": failure_window[-1].timestamp.isoformat()}
            alerts.append(_alert_evidence(alert, failure_window))

        # 2. Success after failures for the same user (deduplicating rapid subsequent sessions)
        for username in {user for source, user in successes_by_ip_user if source == ip}:
            user_failures = failures_by_ip_user[(ip, username)]
            last_alerted_success = None
            for success in successes_by_ip_user[(ip, username)]:
                success_key = (success.timestamp, success.line_number)
                prior = [f for f in user_failures
                         if (f.timestamp, f.line_number) < success_key
                         and success.timestamp - f.timestamp <= window
                         and (last_alerted_success is None or (f.timestamp, f.line_number) > last_alerted_success)]
                if len(prior) < thresholds.failures:
                    continue
                alert = {"type": "success_after_failures", "severity": "high", "source_ip": ip,
                         "username": username, "count": len(prior), "window_minutes": thresholds.window_minutes,
                         "summary": f"Successful authentication for {username} from {ip} followed {len(prior)} matching failures within {thresholds.window_minutes} minutes",
                         "window_start": prior[0].timestamp.isoformat(),
                         "window_end": success.timestamp.isoformat()}
                alerts.append(_alert_evidence(alert, prior + [success]))
                last_alerted_success = success_key

        # 3. Password spray success: multiple usernames failed from source before a success
        for success in successes_by_ip.get(ip, []):
            success_key = (success.timestamp, success.line_number)
            spray_failures = [f for f in failures
                              if (f.timestamp, f.line_number) < success_key
                              and success.timestamp - f.timestamp <= window]
            spray_users = {f.username for f in spray_failures}
            if len(spray_failures) >= thresholds.failures and len(spray_users) >= thresholds.usernames:
                alert = {"type": "spray_success", "severity": "high", "source_ip": ip,
                         "username": success.username, "count": len(spray_failures),
                         "usernames_targeted": sorted(spray_users),
                         "window_minutes": thresholds.window_minutes,
                         "summary": f"Successful authentication for {success.username} from {ip} followed {len(spray_failures)} spray failures across {len(spray_users)} usernames within {thresholds.window_minutes} minutes",
                         "window_start": spray_failures[0].timestamp.isoformat(),
                         "window_end": success.timestamp.isoformat()}
                alerts.append(_alert_evidence(alert, spray_failures + [success]))
                break

    # 4. Multiple usernames attempted from one source
    for ip, activity in ip_users.items():
        for activity_window in _qualifying_rolling_windows(
                activity, window, lambda batch: len({e.username for e in batch}) >= thresholds.usernames):
            usernames = sorted({e.username for e in activity_window})
            if len(usernames) >= thresholds.usernames:
                alert = {"type": "multiple_usernames", "severity": "medium", "source_ip": ip,
                         "count": len(usernames), "usernames": usernames,
                         "window_minutes": thresholds.window_minutes,
                         "summary": f"Source {ip} attempted {len(usernames)} distinct usernames within {thresholds.window_minutes} minutes",
                         "window_start": activity_window[0].timestamp.isoformat(),
                         "window_end": activity_window[-1].timestamp.isoformat()}
                alerts.append(_alert_evidence(alert, activity_window))
    # 5. Single username targeted from multiple sources
    for username, activity in user_ips.items():
        for activity_window in _qualifying_rolling_windows(
                activity, window, lambda batch: len({_network_key(e.source_ip, thresholds.cidr_ipv4, thresholds.cidr_ipv6) for e in batch}) >= thresholds.sources):
            sources = sorted({_network_key(e.source_ip, thresholds.cidr_ipv4, thresholds.cidr_ipv6) for e in activity_window})
            if len(sources) >= thresholds.sources:
                alert = {"type": "multiple_sources", "severity": "medium", "username": username,
                         "count": len(sources), "source_ips": sources,
                         "window_minutes": thresholds.window_minutes,
                         "summary": f"Username {username} was targeted from {len(sources)} distinct sources within {thresholds.window_minutes} minutes",
                         "window_start": activity_window[0].timestamp.isoformat(),
                         "window_end": activity_window[-1].timestamp.isoformat()}
                alerts.append(_alert_evidence(alert, activity_window))
    return sorted(alerts, key=lambda a: (a["type"], a.get("source_ip", a.get("username", ""))))
