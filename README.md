# Sentinel SSH Log Analyzer

Sentinel is a local, read-only command-line tool for finding suspicious patterns in Linux SSH authentication logs. It parses common OpenSSH `sshd` messages from traditional syslog (`auth.log`/`secure`) and ISO-timestamped logs, then prints terminal, JSON, or HTML reports. It uses Python's standard library and requires Python 3.9 or newer.

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
zcat /var/log/auth.log.2.gz | python -m sentinel - --format json
python -m sentinel /var/log/auth.log --format html > report.html
python -m sentinel /var/log/auth.log --serve 8080
python -m sentinel tests/data/auth.log --cidr-v4 24
```

For traditional syslog timestamps the year is not present in the source line. Sentinel uses the current year unless `--year` is supplied, then advances the parsing year on a December-to-January transition. ISO timestamps accept fractional seconds and explicit offsets. Timestamps with an explicit timezone are converted to UTC; timezone-naive timestamps are interpreted in the machine's local timezone and also converted to UTC. Event timestamps are stored as naive UTC values and ordered by timestamp, then source line number. Detection windows use elapsed timestamp differences. Pass `-` to read standard input; filenames ending in `.gz` are decompressed while reading.

Options:

- `--format text|json|html`: report format (terminal, JSON, or interactive HTML).
- `--failures N`: failed events from one IP in the rolling window needed for a repeated-failure alert (default 5).
- `--window MINUTES`: rolling window used by all time-based detection rules (default 10).
- `--usernames N`: distinct usernames seen from one IP needed for an alert (default 5).
- `--sources N`: distinct source IPs seen for one username needed for an alert (default 5).
- `--year YYYY`: year for traditional syslog timestamps.
- `--exit-code`: exit with code 1 if any suspicious activity alerts are detected.
- `--min-severity {low,medium,high}`: filter out alerts below the specified severity.
- `--rules RULE1,RULE2`: include only the listed alert types, such as `repeated_failures,spray_success`.
- `--serve [PORT]`: run a local HTTP server on `127.0.0.1` to browse the interactive report (default port 8080).
- `--cidr-v4 PREFIX`: aggregate IPv4 addresses into a CIDR prefix (for example, `24`) to identify activity across a rotating subnet.
- `--cidr-v6 PREFIX`: aggregate IPv6 addresses into a CIDR prefix (for example, `64`).

## Detection rules

1. **Repeated failures:** at least `--failures` failed authentication events from one source occur in a rolling `--window` interval. Qualifying intervals produce separate alerts without duplicate overlap.
2. **Success after failures:** a success from the same source and username follows at least `--failures` matching failures in the preceding rolling interval. Each qualifying success produces an alert.
3. **One source, multiple usernames:** at least `--usernames` distinct names appear in a source's rolling `--window` interval.
4. **Multiple sources, one username:** at least `--sources` distinct IPs appear for a username in a rolling `--window` interval.
5. **Password spray success:** a success from an IP follows at least `--failures` failures across at least `--usernames` distinct usernames within `--window` minutes.

Every alert includes supporting event time, IP, username, outcome, event type, and input line number. Evidence arrays contain at most 20 records (the first 10 and last 10) and include a `total_count` for the full evidence set. Thresholds count parsed events. CIDR aggregation groups source IPs for source-level rules while preserving individual IPs in event evidence. Paired `Invalid user` and failure records with identical timestamp, PID, source, and username are counted once.

The standalone HTML report includes severity filters, collapsible evidence, and an investigation walkthrough. `--serve` binds only to loopback (`127.0.0.1`) and runs until interrupted; it does not expose the report to the network.

## Validation

```sh
bash scripts/validate.sh
```

This runs unit/integration tests and exercises the JSON CLI on the synthetic sample. The sample includes failed and successful authentication, different sources and usernames, an unrelated session message, and malformed lines. It is synthetic documentation/test data, not a captured system log.

## Limitations

Alerts are suspicious indicators for investigation, not proof of compromise. The rules are deliberately simple: distributed activity, NAT/shared addresses, legitimate user mistakes, automation, and log aggregation can produce false positives; slow or low-volume activity can evade thresholds. Only the listed OpenSSH message forms are recognized. PAM messages, other SSH implementations, journald exports with different prefixes, multiline records, and unusual authentication methods may be skipped. The tool does not correlate identity, geolocation, host context, or successful session activity. Traditional syslog has no year or timezone, so supply `--year` when needed and interpret its time values in the host's local context. Malformed SSH-like lines are counted and skipped; unrelated lines are ignored. Sentinel reads the supplied file only and never contacts remote systems.
