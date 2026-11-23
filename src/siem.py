#!/usr/bin/env python3
"""SIEM Log Analysis Platform - safe local demo.

Parses synthetic Windows / Linux / firewall logs into one schema,
correlates across sources, and writes findings. Standard library only.
"""
import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
WIN_RE = re.compile(r"^(\S+) (\S+) Security (\d+) .*Account: (\S+) Source: (\S+)")
LINUX_FAIL = re.compile(r"sshd\[\d+\]: Failed password for (\S+) from (\S+)")
LINUX_OK = re.compile(r"sshd\[\d+\]: Accepted password for (\S+) from (\S+)")
LINUX_SUDO = re.compile(r"sudo: (\S+) :.*USER=(\S+) ; COMMAND=(.+)$")
FW_RE = re.compile(r"^(\S+) (\S+) (ALLOW|DENY) src=(\S+) dst=(\S+) dport=(\d+) proto=(\S+)")


def event(ts, host, ip, user, kind, severity, raw):
    return {"timestamp": ts, "host": host, "source_ip": ip, "user": user,
            "event": kind, "severity": severity, "raw": raw.strip()}


def parse_windows(path):
    out = []
    for line in open(path, encoding="utf-8"):
        m = WIN_RE.match(line)
        if not m:
            continue
        ts, host, code, user, ip = m.groups()
        kind = "auth_failed" if code == "4625" else "auth_success"
        out.append(event(ts, host, ip, user, kind, "Medium" if kind == "auth_failed" else "Low", line))
    return out


def parse_linux(path):
    out = []
    for line in open(path, encoding="utf-8"):
        # Syslog dates in the demo have no year; normalise to 2026-11-23.
        ts = "2026-11-23T" + line.split()[2] + "Z"
        host = line.split()[3] if len(line.split()) > 3 else "srv-01"
        if (m := LINUX_FAIL.search(line)):
            out.append(event(ts, host, m.group(2), m.group(1), "auth_failed", "Medium", line))
        elif (m := LINUX_OK.search(line)):
            out.append(event(ts, host, m.group(2), m.group(1), "auth_success", "Low", line))
        elif (m := LINUX_SUDO.search(line)):
            out.append(event(ts, host, "", m.group(1), "sudo", "Medium", line))
    return out


def parse_firewall(path):
    out = []
    for line in open(path, encoding="utf-8"):
        m = FW_RE.match(line)
        if not m:
            continue
        ts, host, action, ip, dst, port, proto = m.groups()
        kind = "firewall_deny" if action == "DENY" else "firewall_allow"
        out.append(event(ts, host, ip, "", kind, "Medium" if kind == "firewall_deny" else "Low", line))
    return out


def correlate(events):
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        if e["source_ip"]:
            by_ip[e["source_ip"]].append(e)

    for ip, group in by_ip.items():
        fails = [e for e in group if e["event"] == "auth_failed"]
        if len(fails) >= 5:
            findings.append({"rule": "brute-force-across-sources", "severity": "High",
                             "source_ip": ip, "count": len(fails),
                             "detail": f"{len(fails)} failed logins from {ip} across Windows and Linux logs."})
        denies = [e for e in group if e["event"] == "firewall_deny"]
        if len(denies) >= 5:
            findings.append({"rule": "firewall-deny-storm", "severity": "Medium",
                             "source_ip": ip, "count": len(denies),
                             "detail": f"{len(denies)} firewall denies from {ip}; possible scanning."})
        if fails and any(e["event"] == "auth_success" for e in group):
            findings.append({"rule": "failed-login-then-success", "severity": "High",
                             "source_ip": ip, "count": len(fails),
                             "detail": f"Failed logins from {ip} were followed by a successful login; check for credential compromise."})
    sudo = [e for e in events if e["event"] == "sudo"]
    fails = [e for e in events if e["event"] == "auth_failed"]
    if sudo and fails:
        findings.append({"rule": "sudo-after-failed-login", "severity": "Medium",
                         "source_ip": "", "count": len(sudo),
                         "detail": "A sudo command ran on a host that also saw failed logins; review privilege use."})
    return findings


def main():
    p = argparse.ArgumentParser(description="SIEM Log Analysis Platform (demo)")
    p.add_argument("--windows", default=os.path.join(HERE, "..", "demo_data", "windows.log"))
    p.add_argument("--linux", default=os.path.join(HERE, "..", "demo_data", "linux.log"))
    p.add_argument("--firewall", default=os.path.join(HERE, "..", "demo_data", "firewall.log"))
    p.add_argument("--out", default=os.path.join(HERE, "..", "out", "findings.json"))
    args = p.parse_args()

    events = parse_windows(args.windows) + parse_linux(args.linux) + parse_firewall(args.firewall)
    events.sort(key=lambda e: e["timestamp"])
    findings = correlate(events)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"events_parsed": len(events), "findings": findings, "events": events}, f, indent=2)

    print(f"Events parsed: {len(events)}  ({Counter(e['event'] for e in events)})")
    print(f"Top source IPs: {Counter(e['source_ip'] for e in events if e['source_ip']).most_common(3)}")
    print("\nTimeline:")
    for e in events:
        print(f" {e['timestamp']} {e['host']:6} {e['event']:16} {e['source_ip'] or '-':15} {e['user']}")
    print(f"\nFindings: {len(findings)}")
    for f in findings:
        print(f" [{f['severity']}] {f['rule']}: {f['detail']}")
    print(f"Findings written to {args.out}")


if __name__ == "__main__":
    main()
