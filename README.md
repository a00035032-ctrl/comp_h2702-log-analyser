# COMP_H2702 — Scenario A: Security Log Investigation

Reads data/firewall.log and data/authentication.log, correlates IPs
against data/suspicious_ips.txt, scores risk, writes output/report.txt,
report.json, report.csv.

Synthetic teaching data only.

## Run
    python log_analyser.py

## Requirements
Python 3.10+. Standard library only. No pip install needed.

## Risk ratings
Set in THRESHOLDS at the top of log_analyser.py. HIGH triggers: one IP
with >=20 blocks, >=50 failed logins, any lockout, or >=5 watchlist hits.

## Error handling
Missing files print [ERROR] and the run continues. Malformed lines are
counted and skipped. If nothing parses, [FATAL] and clean exit.