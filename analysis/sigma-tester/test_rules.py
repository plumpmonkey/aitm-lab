#!/usr/bin/env python3
"""Test the Sigma rules in analysis/sigma-rules against the lab's own logs.

Run it from the aitm-lab directory:

    docker compose run --rm sigma

Each rule is converted to a database query by pySigma (the library behind the
sigma command-line tool) and run against the logs that match its logsource:

    product: zeek, service: ssl
        your capture       TLS Client Hellos from every file in captures/
        sample             analysis/sample-data/tls-other-domains.csv
    product: corpsso, service: authentication
        your CorpSSO log   the auth_logs table in CorpSSO's database
        sample             analysis/sample-data/corpsso-with-session-logging.csv
"""
import csv
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

LAB = Path(os.environ.get("LAB_DIR", "/lab"))
RULES = LAB / "analysis" / "sigma-rules"
SAMPLES = LAB / "analysis" / "sample-data"
CAPTURES = LAB / "captures"
IDP_DB = LAB / "idp-data" / "corpsso.db"
SHOW = 25                      # most events printed per log
RULE_WIDTH = 78


# --- Logs ---------------------------------------------------------------------
def capture_log():
    files = sorted(CAPTURES.glob("*.pcap"))
    if not files:
        return None, "no .pcap files in captures/. Was the tcpdump container running during Task 2?"
    rows = []
    for f in files:
        out = subprocess.run(
            ["tshark", "-r", str(f), "-Y", "tls.handshake.type == 1", "-T", "fields",
             "-E", "separator=/t", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
             "-e", "tls.handshake.extensions_server_name"],
            capture_output=True, text=True).stdout
        for line in out.splitlines():
            t, src, dst, sni = (line.split("\t") + ["", "", "", ""])[:4]
            rows.append({"ts": datetime.fromtimestamp(float(t), timezone.utc).isoformat(),
                         "id.orig_h": src, "id.resp_h": dst, "server_name": sni})
    return rows, f"{len(rows)} TLS Client Hellos from {len(files)} capture file(s) in captures/"


def corpsso_log():
    if not IDP_DB.exists():
        return None, ("CorpSSO's database was not found. Start the lab with docker compose up -d; "
                      "if you have already run the clean-up, the log has been deleted.")
    db = sqlite3.connect(f"file:{IDP_DB}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute("SELECT * FROM auth_logs ORDER BY id")]
    return rows, f"{len(rows)} events from CorpSSO's auth_logs table"


def csv_log(name):
    path = SAMPLES / name
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return rows, f"{len(rows)} events from analysis/sample-data/{name}"


LOGS = {
    ("zeek", "ssl"): [
        ("YOUR CAPTURE", capture_log, ["ts", "id.orig_h", "id.resp_h", "server_name"]),
        ("SAMPLE: OTHER DOMAIN NAMES", lambda: csv_log("tls-other-domains.csv"),
         ["ts", "id.orig_h", "id.resp_h", "server_name"]),
    ],
    ("corpsso", "authentication"): [
        ("YOUR CORPSSO LOG", corpsso_log, ["timestamp", "email", "source_ip", "event_type", "session_id"]),
        ("SAMPLE: CORPSSO WITH SESSION LOGGING",
         lambda: csv_log("corpsso-with-session-logging.csv"),
         ["timestamp", "email", "source_ip", "event_type", "session_id"]),
    ],
}
_cache = {}


def load(name, loader):
    if name not in _cache:
        _cache[name] = loader()
    return _cache[name]


# --- Output -------------------------------------------------------------------
def short_time(value):
    m = re.match(r"(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)", str(value or ""))
    return f"{m.group(1)} {m.group(2)}" if m else str(value or "")


def describe(row, cols):
    parts = []
    for c in cols:
        if c not in row:
            continue
        v = row[c]
        if c in ("ts", "timestamp"):
            parts.append(short_time(v))
        elif c == "id.orig_h":
            parts.append(f"{v} ->")
        elif c == "session_id":
            parts.append(f"session {v}" if v else "")
        else:
            parts.append(str(v))
    return "  ".join(p for p in parts if p)


def wrap(text, indent):
    words, lines, line = text.split(), [], ""
    for w in words:
        if len(line) + len(w) + 1 > RULE_WIDTH - len(indent):
            lines.append(line); line = w
        else:
            line = f"{line} {w}".strip()
    lines.append(line)
    return "\n".join(indent + l for l in lines)


# --- Running a rule -----------------------------------------------------------
def run_query(sql, rows):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    cols = sorted({k for r in rows for k in r}) or ["empty"]
    db.execute(f"CREATE TABLE logs ({', '.join(f'`{c}`' for c in cols)})")
    db.executemany(f"INSERT INTO logs VALUES ({', '.join('?' * len(cols))})",
                   [tuple(r.get(c) for c in cols) for r in rows])
    return [dict(r) for r in db.execute(sql)]


def report(name, sql, rows, note, cols, correlation):
    """correlation: None for an ordinary rule, else (field counted, timespan)."""
    print(f"\n  {name}: {note}")
    try:
        hits = run_query(sql, rows)
    except sqlite3.OperationalError as e:
        m = re.search(r"no such column: `?([\w.]+)", str(e))
        if m:
            print(wrap(f"The rule cannot run on this log: the log has no field called "
                       f"{m.group(1)}. A rule can only use fields that the log source records.",
                       "    "))
        else:
            print(f"    The rule could not run on this log: {e}")
        return
    if not correlation:
        if hits:
            print(f"    {len(hits)} match(es):")
            for h in hits[:SHOW]:
                print("      " + describe(h, cols))
            if len(hits) > SHOW:
                print(f"      ... and {len(hits) - SHOW} more")
        else:
            print("    No matches.")
        if name.startswith("SAMPLE"):
            # In a sample, what the rule missed matters as much as what it caught.
            key = lambda r: tuple(str(r.get(c)) for c in cols)
            matched = {key(h) for h in hits}
            missed = [r for r in rows if key(r) not in matched]
            if missed:
                print(f"    Not matched ({len(missed)}):")
                for r in missed[:SHOW]:
                    print("      " + describe(r, cols))
        return
    if not hits:
        print("    No alerts.")
        return
    # A correlation alert lists the events it was built from. The backend
    # raises one alert per qualifying event, so keep the largest per group.
    best = {}
    for h in hits:
        key = h["group_keys"]
        if key not in best or h["event_count"] > best[key]["event_count"]:
            best[key] = h
    print(f"    {len(best)} alert(s):")
    for h in best.values():
        keys = ", ".join(f"{k} = {v}" for k, v in json.loads(h["group_keys"]).items())
        field, span = correlation
        print(f"      ALERT  {keys}: {h['metric_value']} different {field} values within {span}")
        for eid in json.loads(h["event_ids"]):
            row = rows[int(eid.split(":")[-1]) - 1]
            print("        " + describe(row, cols))


def check(path):
    print("=" * RULE_WIDTH)
    print(path.name)
    print("=" * RULE_WIDTH)
    try:
        coll = SigmaCollection.load_ruleset([str(path)])
        rules = list(coll.rules)
    except Exception as e:                       # YAML or Sigma syntax error
        print("  This file could not be read as a Sigma rule:")
        print(wrap(str(e), "    "))
        print("  Check the indentation (spaces, not tabs) and the line it names.")
        return False
    base = [r for r in rules if isinstance(r, SigmaRule)]
    corr = [r for r in rules if isinstance(r, SigmaCorrelationRule)]
    main = corr[-1] if corr else base[-1]
    print(f"  {main.title}  (level: {main.level.name.lower() if main.level else 'not set'})")
    try:
        issues = list(SigmaValidator(validators.values()).validate_rules(iter(rules)))
    except Exception:                            # MITRE data missing from the image
        issues = []
        print("  (Rule checks skipped: rebuild with  docker compose build sigma)")
    for i in issues:
        print(wrap(f"Warning: {i.description}" + (f" ({i.tag})" if hasattr(i, "tag") else ""), "  "))
    try:
        sql = sqliteBackend().convert(coll)[-1]
    except Exception as e:
        print("  pySigma could not turn this rule into a query:")
        print(wrap(str(e), "    "))
        return False
    ls = base[0].logsource if base else None
    key = (ls.product, ls.service) if ls else None
    if key not in LOGS:
        print(wrap(f"No test logs for logsource product: {ls.product if ls else None}, "
                   f"service: {ls.service if ls else None}. Use the logsource from the "
                   "starter rule.", "  "))
        return False
    for name, loader, cols in LOGS[key]:
        rows, note = load(name, loader)
        if rows is None:
            print(f"\n  {name}: not available")
            print(wrap(note, "    "))
            continue
        counted = None
        if corr:
            c = corr[-1]
            counted = (getattr(c.condition, "fieldref", None) or "field", str(c.timespan.spec))
        report(name, sql, rows, note, cols, counted)
    return True


def main():
    files = sorted(RULES.glob("*.yml")) + sorted(RULES.glob("*.yaml"))
    if not files:
        print(f"No rule files found in {RULES}.")
        return 1
    print("Times are UTC.")
    ok = [check(f) for f in files]
    print()
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main())
