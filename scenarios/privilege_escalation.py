#!/usr/bin/env python3
"""
scenarios/privilege_escalation.py — Privilege Escalation Simulation

Simulates a privilege escalation attack on a Linux server:

  - Normal user (jdoe) executes unauthorized sudo command
  - Accesses sensitive files as root
  - Runs the full pipeline: ingest → investigate → execute-actions → approve → execute-approved

Expected AI response:
  - Classification: Privilege Escalation  (or similar)
  - MITRE: T1068 (Exploitation for Privilege Escalation) or T1548.003 (Sudo and Sudo Caching)
  - Actions: isolate_host or disable_account (→ require_approval L6), collect_logs (→ auto-executed L4)

Usage:
    python3 scenarios/privilege_escalation.py [--url http://localhost:8000] [--approver analyst1]
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

DEFAULT_URL   = "http://localhost:8000"
ATTACKER_IP   = "192.168.2.50"
TARGET_HOST   = "linux-server-03"
NORMAL_USER   = "jdoe"
ESCALATED_USER = "root"

SEPARATOR = "=" * 60


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http(method: str, url: str, payload: dict | None = None, timeout: int = 30) -> dict | list:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req  = Request(
        url,
        data    = body,
        headers = {"Content-Type": "application/json"},
        method  = method,
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
    except HTTPError as e:
        body_text = e.read().decode("utf-8")
        print(f"  [ERROR] HTTP {e.code} {method} {url}", file=sys.stderr)
        print(f"  {body_text}", file=sys.stderr)
        raise
    except URLError as e:
        print(f"  [ERROR] Cannot reach {url}: {e.reason}", file=sys.stderr)
        print("  Is the backend running? docker compose up -d backend", file=sys.stderr)
        raise


def get(url):                       return http("GET",  url)
def post(url, payload=None):        return http("POST", url, payload)
def post_slow(url, payload=None):   return http("POST", url, payload, timeout=180)


# ── Alert payload ─────────────────────────────────────────────────────────────

def make_privesc_alert() -> dict:
    """Build a CRITICAL-severity privilege escalation alert."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "rule_id":          "5402",
        "rule_description": "Privilege escalation attempt detected — unauthorized sudo execution",
        "rule_level":       12,        # HIGH — privilege escalation
        "agent_id":         "003",
        "agent_name":       TARGET_HOST,
        "timestamp":        now,
        "full_log": (
            f"{now} {TARGET_HOST} "
            f"sudo: {NORMAL_USER} : command not allowed ; "
            f"TTY=pts/0 ; PWD=/home/{NORMAL_USER} ; USER={ESCALATED_USER} ; "
            f"COMMAND=/usr/bin/passwd root && "
            f"sudo: pam_unix(sudo:session): session opened for user {ESCALATED_USER} by {NORMAL_USER}(uid=1001) && "
            f"cat /etc/shadow attempted by {ESCALATED_USER}"
        ),
        "data": {
            "srcip":   ATTACKER_IP,
            "srcuser": NORMAL_USER,
            "dstuser": ESCALATED_USER,
            "command": f"sudo passwd {ESCALATED_USER}; cat /etc/shadow",
            "tty":     "pts/0",
        },
    }


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run(base_url: str, approver: str) -> bool:
    print(f"\n{SEPARATOR}")
    print("  AI-SOC — SCENARIO 3: PRIVILEGE ESCALATION")
    print(f"{SEPARATOR}\n")

    # ── Step 1: Ingest alert ──────────────────────────────────────────────────
    print("STEP 1 — Ingest privilege escalation alert")
    t0 = time.monotonic()
    alert = make_privesc_alert()
    result = post(f"{base_url}/alerts/ingest", alert)
    incident_id = result.get("incident_id")
    if not incident_id:
        print(f"  [FAIL] No incident_id in response: {result}", file=sys.stderr)
        return False
    severity = result.get("severity", "?")
    print(f"  ✓ Incident created : {incident_id}  severity={severity}")

    # ── Step 2: Investigate ───────────────────────────────────────────────────
    print(f"\nSTEP 2 — AI investigation (may take 10–120s)…")
    t_inv_start = time.monotonic()
    report = post_slow(f"{base_url}/incidents/{incident_id}/investigate")
    t_inv_end   = time.monotonic()
    investigation_time = t_inv_end - t_inv_start

    classification = report.get("classification", "?")
    mitre          = report.get("mitre_technique", "?")
    confidence     = report.get("confidence", 0)
    rag_sources    = report.get("rag_context", [])
    rec_actions    = report.get("recommended_actions", [])

    print(f"  ✓ Classification : {classification}")
    print(f"  ✓ MITRE          : {mitre}")
    print(f"  ✓ Confidence     : {confidence:.0%}")
    print(f"  ✓ RAG sources    : {rag_sources}")
    print(f"  ✓ Investigation  : {investigation_time:.1f}s")
    print(f"  ✓ Recommended actions ({len(rec_actions)}):")
    for a in rec_actions:
        print(f"      - {a.get('action')} → {a.get('target')}  priority={a.get('priority')}")

    # ── Step 3: Safety engine ─────────────────────────────────────────────────
    print(f"\nSTEP 3 — Safety engine (execute-actions)")
    safety_result = post(f"{base_url}/incidents/{incident_id}/execute-actions")
    summary = safety_result.get("summary", {})
    print(f"  ✓ Auto-executed       : {summary.get('auto_executed', 0)}")
    print(f"  ✓ Queued for approval : {summary.get('queued_for_approval', 0)}")
    print(f"  ✓ Blocked by safety   : {summary.get('blocked_by_safety', 0)}")
    for action in safety_result.get("actions", []):
        outcome = action.get("outcome")
        mark    = "✓" if outcome == "auto_executed" else ("⏳" if outcome == "queued_for_approval" else "✗")
        print(f"    {mark} {action.get('action_type'):20s} L{action.get('risk_level')}  → {outcome}")

    # ── Step 4: Show pending approvals ────────────────────────────────────────
    print(f"\nSTEP 4 — Pending approval queue")
    approvals = get(f"{base_url}/approvals")
    our_approvals = [
        ap for ap in approvals
        if (ap.get("action") or {}).get("incident_id") == incident_id
    ]
    if not our_approvals:
        print("  (no pending approvals for this incident)")
    else:
        for ap in our_approvals:
            act = ap.get("action") or {}
            print(f"  ⏳ approval #{ap['id']}  {act.get('action_type')}  "
                  f"target={act.get('target')}  L{act.get('risk_level')}")

    # ── Step 5: Approve ───────────────────────────────────────────────────────
    print(f"\nSTEP 5 — Analyst '{approver}' approves all pending actions")
    approved_count = 0
    for ap in our_approvals:
        decision_result = post(
            f"{base_url}/approvals/{ap['id']}/decide",
            {
                "decision": "approved",
                "approver": approver,
                "reason":   (
                    f"Confirmed privilege escalation: {NORMAL_USER} gained root access "
                    f"and accessed /etc/shadow. Immediate isolation required."
                ),
            },
        )
        act = decision_result.get("action") or {}
        print(f"  ✓ Approved: {act.get('action_type')} on {act.get('target')}")
        approved_count += 1
    if approved_count == 0:
        print("  (nothing to approve)")

    # ── Step 6: Execute approved ──────────────────────────────────────────────
    print(f"\nSTEP 6 — Execute approved actions")
    exec_result = post(f"{base_url}/incidents/{incident_id}/execute-approved")
    executed    = exec_result.get("executed_count", 0)
    print(f"  ✓ Executed {executed} approved action(s)")
    for action in exec_result.get("actions", []):
        print(f"    ✓ {action.get('action_type'):20s} L{action.get('risk_level')}  → {action.get('detail')}")

    # ── Step 7: Audit trail ───────────────────────────────────────────────────
    print(f"\nSTEP 7 — Audit trail for {incident_id}")
    audit = get(f"{base_url}/incidents/{incident_id}/audit")
    seen_types = set()
    for entry in audit:
        event_type = entry.get("event_type", "")
        actor      = entry.get("actor", "")
        ts         = (entry.get("timestamp") or "")[:19].replace("T", " ")
        print(f"  [{ts}] [{actor:10s}] {event_type}")
        seen_types.add(event_type)

    # ── Metrics summary ───────────────────────────────────────────────────────
    print(f"\n{SEPARATOR}")
    print("  METRICS SUMMARY — SCENARIO 3 (Privilege Escalation)")
    print(SEPARATOR)
    print(f"  Incident ID       : {incident_id}")
    print(f"  Classification    : {classification}")
    print(f"  MITRE Technique   : {mitre}")
    print(f"  Confidence        : {confidence:.0%}")
    privesc_keywords = ["privilege", "escalat", "sudo", "T1068", "T1548"]
    detection_ok = any(kw.lower() in classification.lower() or kw in mitre for kw in privesc_keywords)
    print(f"  Detection Correct : {'YES' if detection_ok else 'REVIEW'}")
    print(f"  Investigation time: {investigation_time:.1f}s")
    print(f"  Actions proposed  : {len(rec_actions)}")
    print(f"  Auto-executed     : {summary.get('auto_executed', 0)}")
    print(f"  Queued (approval) : {summary.get('queued_for_approval', 0)}")
    print(f"  Blocked by safety : {summary.get('blocked_by_safety', 0)}")

    expected = [
        "incident.created",
        "incident.investigated",
        "safety.actions_processed",
    ]
    if approved_count > 0:
        expected += ["approval.approved", "action.executed", "remediation.complete"]

    all_pass = True
    print(f"\n  Audit trail checks:")
    for evt in expected:
        ok   = evt in seen_types
        mark = "✓" if ok else "✗"
        print(f"    {mark} {evt}")
        if not ok:
            all_pass = False

    print(f"\n{SEPARATOR}")
    if all_pass:
        print("  ✅  SCENARIO 3 COMPLETE!")
    else:
        print("  ❌  SOME CHECKS FAILED")
    print(f"{SEPARATOR}\n")

    return all_pass


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Privilege Escalation Scenario")
    parser.add_argument("--url",      default=DEFAULT_URL, help="Backend base URL")
    parser.add_argument("--approver", default="analyst1",  help="Analyst username")
    args = parser.parse_args()

    try:
        success = run(args.url, args.approver)
        sys.exit(0 if success else 1)
    except (HTTPError, URLError):
        sys.exit(1)
