#!/usr/bin/env python3
# COMP_H2702 - Scenario A: Security Log Investigation
# Reads firewall + auth logs, checks IPs against a watchlist, scores risk,
# writes output/report.txt, .json, .csv. Run: python log_analyser.py

import csv
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

DATA_DIR = Path("data")
OUTPUT_DIR = Path("output")

# Tune these to change what counts as HIGH / MEDIUM risk.
THRESHOLDS = {
    "blocks_from_one_ip": 20,
    "failed_logins": 50,
    "watchlist_hits": 5,
    "port_blocks": 10,
}

TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
ACTION = re.compile(r"\b(ALLOW|BLOCK|DENY|DROP|ACCEPT|REJECT)\b", re.I)
PORT = re.compile(r":(\d{1,5})\b")
PROTO = re.compile(r"\b(TCP|UDP|ICMP)\b", re.I)
AUTH_EVENT = re.compile(
    r"\b(LOGIN_?SUCCES{1,4}|LOGIN_?FAIL(?:ED|URE)?|ACCOUNT_?LOCK(?:ED|OUT)?|LOCKOUT|LOGOUT)\b",
    re.I,
)
USER = re.compile(r"\b(?:user|username|account)\s*[=:]\s*([A-Za-z0-9._@\-]+)", re.I)


def load_lines(path):
    """Read a text file, return list of non-empty lines. Empty list on error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
    except OSError as exc:
        print(f"[ERROR] Could not read {path}: {exc}")
    return []


def parse_firewall(line):
    """Return a dict for one firewall line, or None if malformed."""
    ts = TS.search(line)
    act = ACTION.search(line)
    ips = IP.findall(line)
    if not (ts and act and ips):
        return None

    action = act.group(1).upper()
    if action in ("DENY", "DROP", "REJECT"):
        action = "BLOCK"
    elif action == "ACCEPT":
        action = "ALLOW"

    # Search for the port AFTER the timestamp so HH:MM:SS doesn't match.
    port_match = PORT.search(line[ts.end():])
    proto = PROTO.search(line)

    return {
        "timestamp": ts.group(1),
        "action": action,
        "src_ip": ips[0],
        "dst_ip": ips[1] if len(ips) > 1 else None,
        "dst_port": int(port_match.group(1)) if port_match else None,
        "protocol": proto.group(1).upper() if proto else None,
    }


def parse_auth(line):
    """Return a dict for one auth line, or None if malformed."""
    ts = TS.search(line)
    ev = AUTH_EVENT.search(line)
    if not (ts and ev):
        return None

    raw = ev.group(1).upper().replace("_", "")
    if "SUCCES" in raw:
        event = "LOGIN_SUCCESS"
    elif "FAIL" in raw:
        event = "LOGIN_FAILED"
    elif "LOCK" in raw:
        event = "ACCOUNT_LOCK"
    elif "LOGOUT" in raw:
        event = "LOGOUT"
    else:
        event = raw

    ips = IP.findall(line)

    # Username: try user=xxx first, then the field after the event token.
    user_match = USER.search(line)
    username = user_match.group(1) if user_match else None
    if username is None:
        for i, part in enumerate(re.split(r"[|,;]", line)):
            if AUTH_EVENT.search(part) and i + 1 < len(re.split(r"[|,;]", line)):
                candidate = re.split(r"[|,;]", line)[i + 1].strip()
                if candidate and not IP.fullmatch(candidate) and not candidate[0].isdigit():
                    username = candidate
                break

    return {
        "timestamp": ts.group(1),
        "event": event,
        "username": username,
        "src_ip": ips[0] if ips else None,
    }


def load_log(path, parser, label):
    """Parse every line in the file. Return (events, malformed_count)."""
    events, bad = [], 0
    for line in load_lines(path):
        parsed = parser(line)
        if parsed:
            events.append(parsed)
        else:
            bad += 1
    print(f"[{label}] {len(events)} valid events, {bad} malformed lines")
    return events, bad


def analyse_firewall(events):
    """Count actions and rank top blocked IPs and ports."""
    blocked = [e for e in events if e["action"] == "BLOCK"]
    return {
        "total_events": len(events),
        "allowed": len([e for e in events if e["action"] == "ALLOW"]),
        "blocked": len(blocked),
        "unique_src_ips": len({e["src_ip"] for e in events if e["src_ip"]}),
        "top_blocked_ips": Counter(e["src_ip"] for e in blocked).most_common(10),
        "top_blocked_ports": Counter(
            e["dst_port"] for e in blocked if e["dst_port"] is not None
        ).most_common(10),
    }


def analyse_auth(events):
    """Count auth events and rank top failing IPs and usernames."""
    types = Counter(e["event"] for e in events)
    failed = [e for e in events if e["event"] == "LOGIN_FAILED"]
    return {
        "total_events": len(events),
        "successes": types.get("LOGIN_SUCCESS", 0),
        "failed": types.get("LOGIN_FAILED", 0),
        "lockouts": types.get("ACCOUNT_LOCK", 0),
        "locked_users": sorted({e["username"] for e in events
                                if e["event"] == "ACCOUNT_LOCK" and e["username"]}),
        "top_failing_ips": Counter(e["src_ip"] for e in failed if e["src_ip"]).most_common(10),
        "top_failing_users": Counter(e["username"] for e in failed if e["username"]).most_common(10),
    }


def correlate(fw, au, path):
    """Match source IPs against the watchlist file."""
    watchlist = set(load_lines(path))
    matched = sorted({e["src_ip"] for e in fw + au
                      if e.get("src_ip") in watchlist})
    return {
        "watchlist_size": len(watchlist),
        "firewall_hits": sum(1 for e in fw if e.get("src_ip") in watchlist),
        "auth_hits": sum(1 for e in au if e.get("src_ip") in watchlist),
        "matched_ips": matched,
    }


def calculate_risk(fw, au, corr):
    """Apply thresholds. Return (rating, findings list of tuples)."""
    findings = []

    if fw["top_blocked_ips"] and fw["top_blocked_ips"][0][1] >= THRESHOLDS["blocks_from_one_ip"]:
        ip, count = fw["top_blocked_ips"][0]
        findings.append(("HIGH", f"Repeated blocks from {ip}",
                         f"{count} BLOCK events from one source"))

    if fw["top_blocked_ports"] and fw["top_blocked_ports"][0][1] >= THRESHOLDS["port_blocks"]:
        port, count = fw["top_blocked_ports"][0]
        findings.append(("MEDIUM", f"Many blocks on port {port}",
                         f"{count} BLOCK events (possible scanning)"))

    if au["failed"] >= THRESHOLDS["failed_logins"]:
        findings.append(("HIGH", "Elevated failed logins",
                         f"{au['failed']} LOGIN_FAILED events"))

    if au["lockouts"] > 0:
        findings.append(("HIGH", "Account lockouts",
                         f"{au['lockouts']} lockouts: {', '.join(au['locked_users'])}"))

    hits = corr["firewall_hits"] + corr["auth_hits"]
    if hits >= THRESHOLDS["watchlist_hits"]:
        findings.append(("HIGH", "Watchlist IPs active in logs",
                         f"{hits} events from {len(corr['matched_ips'])} watchlist IP(s)"))
    elif corr["matched_ips"]:
        findings.append(("MEDIUM", "Watchlist IP activity detected",
                         "Matched: " + ", ".join(corr["matched_ips"])))

    severities = [f[0] for f in findings]
    if "HIGH" in severities:
        rating = "HIGH"
    elif "MEDIUM" in severities:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    findings.sort(key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f[0]])
    return rating, findings


def write_reports(fw, au, corr, rating, findings):
    """Print to console and save report.txt, report.json, report.csv."""
    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"[ERROR] Could not create output directory: {exc}")
        return

    print("\n" + "=" * 60)
    print("INVESTIGATION SUMMARY")
    print("=" * 60)
    print(f"Risk rating    : {rating}")
    print(f"Firewall events: {fw['total_events']} "
          f"(ALLOW={fw['allowed']}, BLOCK={fw['blocked']}, "
          f"unique_src={fw['unique_src_ips']})")
    print(f"Auth events    : {au['total_events']} "
          f"(SUCCESS={au['successes']}, FAILED={au['failed']}, "
          f"LOCKOUTS={au['lockouts']})")
    print(f"Watchlist hits : {len(corr['matched_ips'])} of {corr['watchlist_size']} IPs")

    print("\nTop blocked source IPs:")
    for ip, count in fw["top_blocked_ips"][:5]:
        print(f"  {ip:<18} {count}")

    print("\nTop blocked ports:")
    for port, count in fw["top_blocked_ports"][:5]:
        print(f"  {port:<18} {count}")

    print("\nTop failing-login IPs:")
    for ip, count in au["top_failing_ips"][:5]:
        print(f"  {ip:<18} {count}")

    print("\nTop targeted usernames:")
    for user, count in au["top_failing_users"][:5]:
        print(f"  {user:<18} {count}")

    print("\nFindings:")
    for i, (sev, title, evidence) in enumerate(findings, 1):
        print(f"  [{i}] {sev}: {title}")
        print(f"      {evidence}")

    with open(OUTPUT_DIR / "report.txt", "w", encoding="utf-8") as fh:
        fh.write("SECURITY LOG INVESTIGATION REPORT\n")
        fh.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")
        fh.write(f"Overall risk: {rating}\n\n")
        fh.write(f"Firewall: {fw['total_events']} events, "
                 f"{fw['allowed']} ALLOW, {fw['blocked']} BLOCK, "
                 f"{fw['unique_src_ips']} unique source IPs\n")
        fh.write(f"Auth: {au['total_events']} events, "
                 f"{au['successes']} SUCCESS, {au['failed']} FAILED, "
                 f"{au['lockouts']} LOCKOUT\n")
        fh.write(f"Watchlist: {len(corr['matched_ips'])} of "
                 f"{corr['watchlist_size']} IPs matched\n\n")
        fh.write("RANKED FINDINGS\n")
        for i, (sev, title, evidence) in enumerate(findings, 1):
            fh.write(f"  [{i}] {sev}: {title}\n      {evidence}\n")

    with open(OUTPUT_DIR / "report.json", "w", encoding="utf-8") as fh:
        json.dump(
            {"generated": datetime.now().isoformat(timespec="seconds"),
             "risk": rating,
             "firewall": fw, "authentication": au,
             "correlation": corr,
             "findings": [{"severity": s, "title": t, "evidence": e}
                          for s, t, e in findings]},
            fh, indent=2,
        )

    with open(OUTPUT_DIR / "report.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["section", "metric", "value"])
        w.writerow(["overall", "risk_rating", rating])
        w.writerow(["firewall", "total_events", fw["total_events"]])
        w.writerow(["firewall", "allowed", fw["allowed"]])
        w.writerow(["firewall", "blocked", fw["blocked"]])
        w.writerow(["firewall", "unique_src_ips", fw["unique_src_ips"]])
        for ip, count in fw["top_blocked_ips"]:
            w.writerow(["firewall_top_ip", ip, count])
        for port, count in fw["top_blocked_ports"]:
            w.writerow(["firewall_top_port", port, count])
        w.writerow(["auth", "total_events", au["total_events"]])
        w.writerow(["auth", "successes", au["successes"]])
        w.writerow(["auth", "failed", au["failed"]])
        w.writerow(["auth", "lockouts", au["lockouts"]])
        for ip, count in au["top_failing_ips"]:
            w.writerow(["auth_top_failing_ip", ip, count])
        for user, count in au["top_failing_users"]:
            w.writerow(["auth_top_failing_user", user, count])
        w.writerow(["watchlist", "size", corr["watchlist_size"]])
        w.writerow(["watchlist", "matched", len(corr["matched_ips"])])
        for i, (sev, title, _) in enumerate(findings, 1):
            w.writerow(["finding", f"#{i} {sev}", title])

    print("\nReports written to output/")


def main():
    """Load, analyse, correlate, score and report."""
    print("COMP_H2702 - Security Log Investigation")
    fw_events, _ = load_log(DATA_DIR / "firewall.log", parse_firewall, "firewall")
    au_events, _ = load_log(DATA_DIR / "authentication.log", parse_auth, "auth")

    if not fw_events and not au_events:
        print("[FATAL] No events parsed from either log. Check data/ folder.")
        return

    fw = analyse_firewall(fw_events)
    au = analyse_auth(au_events)
    corr = correlate(fw_events, au_events, DATA_DIR / "suspicious_ips.txt")
    rating, findings = calculate_risk(fw, au, corr)
    write_reports(fw, au, corr, rating, findings)

if __name__ == "__main__":
    main()