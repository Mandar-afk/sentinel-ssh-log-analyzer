"""Terminal and JSON report rendering."""
import html
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


def render_html(report):
    """Render a standalone, zero-dependency interactive HTML security report."""
    source_escaped = html.escape(str(report.get("source", "unknown")))
    assessment_escaped = html.escape(str(report.get("assessment", "")))
    alerts = report.get("alerts", [])
    events_count = report.get("events_parsed", 0)
    malformed_count = report.get("malformed_lines", 0)
    high_count = sum(1 for a in alerts if a.get("severity") == "high")
    med_count = sum(1 for a in alerts if a.get("severity") == "medium")

    alert_cards = []
    for idx, alert in enumerate(alerts, 1):
        sev = html.escape(str(alert.get("severity", "medium")).lower())
        atype = html.escape(str(alert.get("type", "unknown")))
        summary = html.escape(str(alert.get("summary", "")))
        count = alert.get("total_count", alert.get("count", 0))
        wstart = html.escape(str(alert.get("window_start", "N/A")))
        wend = html.escape(str(alert.get("window_end", "N/A")))

        evidence_rows = []
        for ev in alert.get("evidence", []):
            line_no = html.escape(str(ev.get("line", "")))
            etime = html.escape(str(ev.get("time", "")))
            eip = html.escape(str(ev.get("source_ip", "")))
            euser = html.escape(str(ev.get("username", "")))
            eout = html.escape(str(ev.get("outcome", "")))
            ekind = html.escape(str(ev.get("event_type", "")))
            out_class = "out-success" if eout == "success" else "out-failure"
            evidence_rows.append(
                f"<tr><td>line {line_no}</td><td>{etime}</td><td><code>{eip}</code></td>"
                f"<td><code>{euser}</code></td><td class='{out_class}'>{eout}</td><td>{ekind}</td></tr>"
            )
        evidence_html = "\n".join(evidence_rows)

        alert_cards.append(f"""
        <div class="alert-card sev-{sev}" data-severity="{sev}">
            <div class="alert-header">
                <div>
                    <span class="badge badge-{sev}">{sev.upper()}</span>
                    <strong class="alert-type">{atype}</strong>
                    <div class="alert-summary">{summary}</div>
                </div>
                <div class="alert-meta">
                    <div>Window: {wstart} &rarr; {wend}</div>
                    <div>Evidence: {count} events</div>
                </div>
            </div>
            <details class="evidence-details">
                <summary>Inspect Event Evidence Table ({len(alert.get('evidence', []))} shown)</summary>
                <div class="table-container">
                    <table class="evidence-table">
                        <thead>
                            <tr><th>Source Line</th><th>Timestamp (UTC)</th><th>IP / Subnet</th><th>Username</th><th>Outcome</th><th>Event Type</th></tr>
                        </thead>
                        <tbody>
                            {evidence_html}
                        </tbody>
                    </table>
                </div>
            </details>
        </div>
        """)

    alerts_rendered = "\n".join(alert_cards) if alert_cards else "<div class='empty-state'>No configured suspicious activity patterns detected.</div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sentinel Security Report: {source_escaped}</title>
    <style>
        :root {{
            --bg: #0f172a; --surface: #1e293b; --surface-border: #334155;
            --text: #f8fafc; --text-muted: #94a3b8; --high: #ef4444;
            --med: #f59e0b; --low: #3b82f6; --success: #10b981; --accent: #6366f1;
        }}
        @media (prefers-color-scheme: light) {{
            :root {{
                --bg: #f8fafc; --surface: #ffffff; --surface-border: #cbd5e1;
                --text: #0f172a; --text-muted: #475569; --high: #dc2626;
                --med: #b45309; --low: #2563eb; --success: #047857; --accent: #4f46e5;
            }}
            .guide-box h2, .step-title, .alert-summary {{ color: #1e293b; }}
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg); color: var(--text); margin: 0; padding: 24px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ border-bottom: 1px solid var(--surface-border); padding-bottom: 20px; margin-bottom: 24px; }}
        h1 {{ margin: 0 0 8px 0; font-size: 26px; display: flex; align-items: center; gap: 10px; }}
        .log-source {{ color: var(--text-muted); font-size: 14px; word-break: break-all; }}
        .assessment-banner {{
            background: rgba(99, 102, 241, 0.15); border-left: 4px solid var(--accent);
            padding: 12px 16px; margin: 20px 0; border-radius: 4px; font-size: 14px;
        }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .card {{
            background: var(--surface); border: 1px solid var(--surface-border);
            border-radius: 8px; padding: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}
        .card-val {{ font-size: 28px; font-weight: bold; margin-top: 4px; }}
        .card-label {{ color: var(--text-muted); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .guide-box {{
            background: var(--surface); border: 1px solid var(--surface-border);
            border-radius: 8px; padding: 20px; margin-bottom: 28px;
        }}
        .guide-box h2 {{ margin-top: 0; font-size: 18px; color: #cbd5e1; }}
        .guide-steps {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }}
        .step-num {{ display: inline-block; width: 22px; height: 22px; border-radius: 50%; background: var(--accent); text-align: center; font-size: 13px; line-height: 22px; margin-right: 6px; }}
        .step-title {{ font-weight: bold; font-size: 14px; color: #e2e8f0; }}
        .step-desc {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; line-height: 1.4; }}
        .filter-bar {{ display: flex; gap: 10px; margin-bottom: 16px; }}
        .filter-btn {{
            background: var(--surface); border: 1px solid var(--surface-border);
            color: var(--text); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px;
        }}
        .filter-btn.active {{ background: var(--accent); border-color: var(--accent); }}
        .alert-card {{
            background: var(--surface); border-radius: 8px; border: 1px solid var(--surface-border);
            margin-bottom: 16px; overflow: hidden;
        }}
        .alert-card.sev-high {{ border-left: 5px solid var(--high); }}
        .alert-card.sev-medium {{ border-left: 5px solid var(--med); }}
        .alert-header {{ padding: 16px; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }}
        .alert-type {{ font-size: 16px; margin-left: 8px; }}
        .alert-summary {{ margin-top: 6px; color: #e2e8f0; font-size: 14px; }}
        .alert-meta {{ text-align: right; font-size: 12px; color: var(--text-muted); min-width: 200px; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; letter-spacing: 0.5px; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--med); color: #000; }}
        .evidence-details {{ background: rgba(15, 23, 42, 0.4); border-top: 1px solid var(--surface-border); }}
        .evidence-details summary {{ padding: 12px 16px; cursor: pointer; font-size: 13px; color: var(--text-muted); }}
        .table-container {{ overflow-x: auto; padding: 0 16px 16px 16px; }}
        .evidence-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        .evidence-table th, .evidence-table td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--surface-border); }}
        .evidence-table th {{ color: var(--text-muted); font-size: 12px; font-weight: 600; text-transform: uppercase; }}
        .out-success {{ color: var(--success); font-weight: 600; }}
        .out-failure {{ color: var(--high); }}
        .empty-state {{ text-align: center; padding: 40px; color: var(--text-muted); font-size: 16px; }}
        @media (max-width: 640px) {{
            body {{ padding: 14px; }}
            .alert-header {{ display: block; }}
            .alert-meta {{ text-align: left; margin-top: 12px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>&#128737; Sentinel Security Investigation Report</h1>
            <div class="log-source">Analyzed Source: <code>{source_escaped}</code></div>
            <div class="assessment-banner">
                <strong>Notice:</strong> {assessment_escaped}
            </div>
        </header>

        <section class="grid">
            <div class="card"><div class="card-label">Events Parsed</div><div class="card-val">{events_count}</div></div>
            <div class="card"><div class="card-label">Malformed Lines</div><div class="card-val">{malformed_count}</div></div>
            <div class="card"><div class="card-label">Total Alerts</div><div class="card-val">{len(alerts)}</div></div>
            <div class="card"><div class="card-label">High Severity Alerts</div><div class="card-val" style="color:var(--high);">{high_count}</div></div>
        </section>

        <section class="guide-box">
            <h2>&#128214; Step-by-Step Incident Investigation Guide (Third-Party Analyst Walkthrough)</h2>
            <div class="guide-steps">
                <div>
                    <div><span class="step-num">1</span><span class="step-title">Initial Triage</span></div>
                    <div class="step-desc">Focus on <code>HIGH</code> severity indicators: <code>success_after_failures</code> and <code>spray_success</code> represent potential successful credential compromises.</div>
                </div>
                <div>
                    <div><span class="step-num">2</span><span class="step-title">Scope &amp; Attribution</span></div>
                    <div class="step-desc">Check whether the source IP or subnet belongs to expected internal, NAT, or VPN traffic. Multiple usernames from one source can indicate password guessing.</div>
                </div>
                <div>
                    <div><span class="step-num">3</span><span class="step-title">Evidence Verification</span></div>
                    <div class="step-desc">Use the evidence table's source line number to locate the event in the analyzed log. Correlate with authorized identity and session records.</div>
                </div>
                <div>
                    <div><span class="step-num">4</span><span class="step-title">Response Planning</span></div>
                    <div class="step-desc">Treat alerts as indicators, not proof of compromise. Follow the system owner's incident process to verify activity and decide whether containment is warranted.</div>
                </div>
            </div>
        </section>

        <h2>Detected Suspicious Activity Alerts</h2>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterSev('all', this)">All ({len(alerts)})</button>
            <button class="filter-btn" onclick="filterSev('high', this)">High ({high_count})</button>
            <button class="filter-btn" onclick="filterSev('medium', this)">Medium ({med_count})</button>
        </div>

        <div id="alerts-container">
            {alerts_rendered}
        </div>
    </div>

    <script>
        function filterSev(sev, btn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.querySelectorAll('.alert-card').forEach(card => {{
                if (sev === 'all' || card.getAttribute('data-severity') === sev) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""
