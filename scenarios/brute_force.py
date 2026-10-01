#!/usr/bin/env python3
"""
scenarios/brute_force.py — Brute Force SSH Attack Simulation

Simulates a brute-force SSH attack:
  - 10 failed login attempts from attacker IP
  - 1 successful login (account compromise)

Sends alerts to POST /alerts/ingest and prints the resulting incident IDs.

Usage:
    python3 scenarios/brute_force.py [--url http://localhost:8000]

Wazuh rule IDs used:
  5710 — sshd: Attempt to login using a denied user
  5716 — sshd: Multiple authentication failures
  5715 — sshd: Authentication success

Expected outcome:
  - 2 incidents created (one for brute force, one for success after failures)
  - Both visible at GET /incidents/
  - Severity: MEDIUM for rule level 10, HIGH for rule level 12
"""

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ── Configuration ─────────────────────────────────────────────────────────────
DEFAULT_URL      = "http://localhost:8000"
ATTACKER_IP      = "192.168.1.100"
TARGET_HOST      = "web-server-01"
TARGET_AGENT_ID  = "001"
TARGET_USER      = "admin"
NUM_FAILURES     = 10


def post_json(url: str, payload: dict) -> dict:
    """POST a JSON payload and return the parsed response."""
    body = json.dumps(payload).encode("utf-8")
    req  = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"  [ERROR] HTTP {e.code}: {body}", file=sys.stderr)
        raise
    except URLError as e:
        print(f"  [ERROR] Cannot reach {url}: {e.reason}", file=sys.stderr)
        print("  Is the backend running? Try: docker compose up -d backend", file=sys.stderr)
        raise


def run_simulation(base_url: str):
    ingest_url = f"{base_url}/alerts/ingest"
    print(f"\n{'='*60}")
    print("  AI-SOC — Brute Force SSH Simulation")
    print(f"  Target: {base_url}")
    print(f"{'='*60}\n")

    start_time = datetime.now(tz=timezone.utc)
    results = []

    # ── Phase 1: Failed login attempts ───────────────────────────────────────
    print(f"[*] Sending {NUM_FAILURES} failed SSH login attempts...")
    for i in range(NUM_FAILURES):
        event_time = start_time + timedelta(seconds=i * 3)
        alert = {
            "rule_id":          "5710",
            "rule_description": "sshd: Attempt to login using a denied user",
            "rule_level":       5,          # LOW — individual failure
            "agent_name":       TARGET_HOST,
            "agent_id":         TARGET_AGENT_ID,
            "timestamp":        event_time.isoformat(),
            "full_log": (
                f"{event_time.strftime('%b %d %H:%M:%S')} {TARGET_HOST} "
                f"sshd[{1000+i}]: Invalid user {TARGET_USER} from {ATTACKER_IP} port {50000+i}"
            ),
            "data": {
                "srcip":    ATTACKER_IP,
                "srcuser":  TARGET_USER,
                "protocol": "ssh",
                "attempt":  i + 1,
            },
        }
        resp = post_json(ingest_url, alert)
        results.append(resp)
        print(f"  [{i+1:02d}] incident={resp['incident_id']}  severity={resp['severity']}")

    # ── Phase 2: Brute force aggregate alert ─────────────────────────────────
    print(f"\n[*] Sending brute-force aggregate alert (rule 5716, level 10)...")
    brute_time = start_time + timedelta(seconds=NUM_FAILURES * 3)
    brute_alert = {
        "rule_id":          "5716",
        "rule_description": "sshd: Multiple authentication failures",
        "rule_level":       10,         # MEDIUM — multiple failures
        "agent_name":       TARGET_HOST,
        "agent_id":         TARGET_AGENT_ID,
        "timestamp":        brute_time.isoformat(),
        "full_log": (
            f"{brute_time.strftime('%b %d %H:%M:%S')} {TARGET_HOST} "
            f"sshd[9999]: {NUM_FAILURES} authentication failures for {TARGET_USER} "
            f"from {ATTACKER_IP} port 51000 ssh2"
        ),
        "data": {
            "srcip":        ATTACKER_IP,
            "srcuser":      TARGET_USER,
            "protocol":     "ssh",
            "failure_count": NUM_FAILURES,
        },
    }
    resp = post_json(ingest_url, brute_alert)
    results.append(resp)
    print(f"  Brute force incident={resp['incident_id']}  severity={resp['severity']}")

    # ── Phase 3: Successful login after failures ──────────────────────────────
    print(f"\n[*] Sending successful login alert (rule 5715, level 12 — HIGH)...")
    success_time = start_time + timedelta(seconds=NUM_FAILURES * 3 + 10)
    success_alert = {
        "rule_id":          "5715",
        "rule_description": "sshd: Authentication success after multiple failures (possible account compromise)",
        "rule_level":       12,         # HIGH — success after brute force
        "agent_name":       TARGET_HOST,
        "agent_id":         TARGET_AGENT_ID,
        "timestamp":        success_time.isoformat(),
        "full_log": (
            f"{success_time.strftime('%b %d %H:%M:%S')} {TARGET_HOST} "
            f"sshd[9999]: Accepted password for {TARGET_USER} from {ATTACKER_IP} port 51001 ssh2"
        ),
        "data": {
            "srcip":            ATTACKER_IP,
            "srcuser":          TARGET_USER,
            "protocol":         "ssh",
            "prior_failures":   NUM_FAILURES,
            "compromise_risk":  "HIGH",
        },
    }
    resp = post_json(ingest_url, success_alert)
    results.append(resp)
    print(f"  Compromise incident={resp['incident_id']}  severity={resp['severity']}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Simulation complete. {len(results)} incidents created.")
    print(f"{'='*60}")
    print(f"\n  Verify with:")
    print(f"    curl {base_url}/incidents/ | python3 -m json.tool")
    print(f"\n  Or check Adminer: http://localhost:8080")
    print(f"    SELECT * FROM incidents ORDER BY created_at DESC LIMIT 5;")
    print(f"    SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 5;\n")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute Force SSH Attack Simulation")
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Backend base URL (default: {DEFAULT_URL})",
    )
    args = parser.parse_args()

    try:
        run_simulation(args.url)
    except (HTTPError, URLError):
        sys.exit(1)
