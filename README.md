# Sentinel SSH Log Analyzer

Sentinel is a local, read-only command-line tool for finding suspicious patterns in Linux SSH authentication logs. It parses common OpenSSH `sshd` messages from traditional syslog (`auth.log`/`secure`) and ISO-timestamped logs, then prints a terminal report or JSON. It uses Python's standard library and requires Python 3.9 or newer.

## Setup

No third-party runtime packages are needed. From this directory, optionally create a project-local virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Run directly without installation using `python -m sentinel`; after installation use `sentinel`.

## Usage

```sh
python -m sentinel tests/data/auth.log --year 2026
python -m sentinel /var/log/auth.log --format json > report.json
python -m sentinel /var/log/secure --failures 8 --usernames 6 --sources 6 --window 15
```

For traditional syslog timestamps the year is not present in the source line. Sentinel uses the current year unless `--year` is supplied. Timestamps with an explicit timezone are converted to UTC; timezone-naive timestamps are interpreted in the machine's local timezone and also converted to UTC. Event timestamps are stored as naive UTC values and ordered by timestamp, then source line number. Detection windows use elapsed timestamp differences.

Options:

- `--format text|json`: readable terminal output (default) or machine-readable JSON.
- `--failures N`: failed events from one IP in the rolling window needed for a repeated-failure alert (default 5).
- `--window MINUTES`: rolling window for repeated failures and success-after-failures (default 10).
- `--usernames N`: distinct usernames seen from one IP needed for an alert (default 5).
- `--sources N`: distinct source IPs seen for one username needed for an alert (default 5).
- `--year YYYY`: year for traditional syslog timestamps.

## Detection rules

1. **Repeated failures:** at least `--failures` failed authentication events from one source occur within a rolling `--window` interval.
2. **Success after failures:** a success from the same source follows at least `--failures` failures in the preceding rolling interval. Evidence includes the prior failures and the success.
3. **One source, multiple usernames:** at least `--usernames` distinct names appear in parsed auth events from a source during the input log.
4. **Multiple sources, one username:** at least `--sources` distinct IPs appear for a username during the input log.

Every alert includes supporting event time, IP, username, outcome, event type, and input line number. Thresholds count parsed events; username/source diversity rules cover the full input file, while failure rules use the configured rolling interval.

## Validation

```sh
bash scripts/validate.sh
```

This runs unit/integration tests and exercises the JSON CLI on the synthetic sample. The sample includes failed and successful authentication, different sources and usernames, an unrelated session message, and malformed lines. It is synthetic documentation/test data, not a captured system log.

## Limitations

Alerts are suspicious indicators for investigation, not proof of compromise. The rules are deliberately simple: distributed activity, NAT/shared addresses, legitimate user mistakes, automation, and log aggregation can produce false positives; slow or low-volume activity can evade thresholds. Only the listed OpenSSH message forms are recognized. PAM messages, other SSH implementations, journald exports with different prefixes, multiline records, and unusual authentication methods may be skipped. The tool does not correlate identity, geolocation, host context, or successful session activity. Traditional syslog has no year or timezone, so supply `--year` when needed and interpret its time values in the host's local context. Malformed SSH-like lines are counted and skipped; unrelated lines are ignored. Sentinel reads the supplied file only and never contacts remote systems.
