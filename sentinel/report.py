"""Terminal and JSON report rendering."""
import json


def make_report(events, alerts, malformed, source):
    return {"source": source, "events_parsed": len(events), "malformed_lines": malformed,
            "alerts": alerts, "assessment": "Suspicious indicators require investigation; they are not proof of compromise."}


def render_json(report):
    return json.dumps(report, indent=2, sort_keys=True)


def render_terminal(report):
    lines = [f"Sentinel SSH log analysis: {report['source']}",
             f"Authentication events parsed: {report['events_parsed']}",
             f"Malformed SSH-like lines skipped: {report['malformed_lines']}",
             f"Alerts: {len(report['alerts'])}"]
    if not report["alerts"]:
        lines.append("No configured suspicious patterns detected.")
    for alert in report["alerts"]:
        lines.extend([f"\n[{alert['severity'].upper()}] {alert['type']}: {alert['summary']}",
                      f"Evidence: {alert['total_count']} records ({len(alert['evidence'])} shown)"])
        for item in alert["evidence"]:
            lines.append(f"  line {item['line']}: {item['time']} {item['source_ip']} {item['outcome']} {item['username']} ({item['event_type']})")
    lines.append(f"\n{report['assessment']}")
    return "\n".join(lines)
