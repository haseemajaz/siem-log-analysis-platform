# Architecture - SIEM Log Analysis Platform

## Data flow

```
demo_data/windows.log  --\
demo_data/linux.log    --->  parsers (one function per source)
demo_data/firewall.log --/       |
                                v
                     normaliser -> common event schema
                                |
                     correlation engine -> findings
                                |
                     out/findings.json + terminal timeline
```

## Common event schema

```json
{"timestamp": "2026-11-23T09:01:00Z", "host": "ws-01", "source_ip": "203.0.113.10",
 "user": "admin", "event": "auth_failed", "severity": "Medium", "raw": "<original line>"}
```

Every parser returns this schema. Correlation rules only ever read the schema,
never raw log text, so a new source only needs a new parser.

## Correlation rules (in `src/siem.py`)

1. **Brute force across sources** - 5+ `auth_failed` from one IP in any source.
2. **Failed login then success** - same IP/user fails, then succeeds within 15 minutes.
3. **Firewall deny storm** - 5+ denies from one IP, suggesting scanning or a blocked attack.
4. **Sudo after failed login** - privilege escalation attempt after a failed login on the same host.

## How to extend

1. Write a parser returning the common schema and register it in `parse_all()`.
2. Add a correlation function and register it in `CORRELATIONS`.
3. Add demo lines to `demo_data/` and check `out/findings.json`.

## Limitations (honest)

- Parsers are regex-based for the demo formats, not full Windows Event Log / syslog parsers.
- No indexing or retention: events are held in memory for one run.
- No live tailing: this is batch analysis of a file, the skill the code demonstrates is parsing and correlation.
