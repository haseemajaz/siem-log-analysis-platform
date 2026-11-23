# 02 - SIEM Log Analysis Platform

A minimal SIEM in pure Python (standard library only). It parses synthetic Windows, Linux and firewall logs into one normalised schema, correlates events across sources, and produces a timeline and a summary an analyst can act on.

No live logs, no agents, no network calls. All logs in `demo_data/` are synthetic.

## What it does

- Parses 3 log formats: Windows Security (4625 failed logon, 4624 success), Linux syslog (sshd, sudo), and firewall (allow/deny)
- Normalises every line to `{timestamp, host, source_ip, user, event, severity, raw}`
- Correlates across sources: failed logins followed by a firewall allow from the same IP, sudo after a failed login, and repeated denies from one IP
- Prints a timeline, top talkers, and correlation findings
- Writes `out/findings.json`

## How to run

```bash
cd 02-siem-log-analysis-platform
python3 src/siem.py --windows demo_data/windows.log --linux demo_data/linux.log --firewall demo_data/firewall.log --out out/findings.json
```

Expected output: about 20 events parsed, 4 correlation findings, including a brute-force pattern from 203.0.113.10.

## Files

- `src/siem.py` - parsers, normaliser, correlation engine, report
- `demo_data/windows.log` - synthetic Windows Security log lines
- `demo_data/linux.log` - synthetic Linux sshd/sudo syslog lines
- `demo_data/firewall.log` - synthetic firewall allow/deny lines
- `docs/architecture.md` - architecture and how to add a new log source
- `requirements.txt` - standard library only

## What an employer sees

Log parsing, normalisation, and cross-source correlation, the core of SIEM work, in readable code with a clear schema. The next step is adding a parser for a fourth source and a rule for it.
