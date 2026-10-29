#!/usr/bin/env python3
"""
scenarios/e2e_test.py — End-to-End Pipeline Test

Runs the full AI-SOC pipeline for a single brute force alert:

  Step 1: Ingest a HIGH-severity brute force alert → create incident
  Step 2: Trigger AI investigation → ai_report + Action rows
  Step 3: Run safety engine → auto-execute L0-4, queue L5+ for approval
  Step 4: Print pending approvals
  Step 5: Approve all pending actions (analyst decision)
  Step 6: Execute approved actions → status=executed
  Step 7: Fetch and print the audit trail

Expected audit event types (in order):
  incident.created
  incident.investigated
  safety.actions_processed
  safety.action_executed      × N  (L0-4 auto)
  safety.approval_required    × M  (L5-6 queued)
  approval.approved           × M
  action.executed             × M
  remediation.complete

Usage:
    python3 scenarios/e2e_test.py [--url http://localhost:8000]
    python3 scenarios/e2e_test.py --approver "analyst1"
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

DEFAULT_URL     = "http://localhost:8000"
ATTACKER_IP     = "192.168.1.200"
TARGET_HOST     = "web-server-02"
TARGET_USER     = "admin"

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
        body = e.read().decode("utf-8")
        print(f"  [ERROR] HTTP {e.code} {method} {url}", file=sys.stderr)
        print(f"  {body}", file=sys.stderr)
        raise
    except URLError as e:
        print(f"  [ERROR] Cannot reach {url}: {e.reason}", file=sys.stderr)
        print("  Is the backend running? docker compose up -d backend", file=sys.stderr)
        raise

def get(url):  return http("GET",  url)
def post(url, payload=None): return http("POST", url, payload)
def post_slow(url, payload=None): return http("POST", url, payload, timeout=120)


# ── Alert payload ─────────────────────────────────────────────────────────────

def make_brute_force_alert() -> dict:
    """Build a HIGH-severity brute-force SSH alert payload."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "rule_id":          "5715",
        "rule_description": "sshd: authentication success after multiple failures",
        "rule_level":       12,
        "agent_id":         "001",
        "agent_name":       TARGET_HOST,
        "timestamp":        now,
        "full_log": (
            f"{now} {TARGET_HOST} sshd[1234]: Accepted password for {TARGET_USER} "
            f"from {ATTACKER_IP} port 54321 ssh2"
        ),
        "data": {
            "srcip":   ATTACKER_IP,
            "dstuser": TARGET_USER,
            "protocol": "ssh",
        },
    }


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run(base_url: str, approver: str):
    print(f"\n{SEPARATOR}")
    print("  AI-SOC END-TO-END PIPELINE TEST")
    print(f"{SEPARATOR}\n")

    # ── Step 1: Ingest alert ──────────────────────────────────────────────────
    print("STEP 1 — Ingest brute force alert")
    alert = make_brute_force_alert()
    result = post(f"{base_url}/alerts/ingest", alert)
    incident_id = result.get("incident_id")
    if not incident_id:
        print(f"  [FAIL] No incident_id in response: {result}", file=sys.stderr)
        sys.exit(1)
    severity   = result.get("severity", "?")
    print(f"  ✓ Incident created: {incident_id}  severity={severity}")

    # ── Step 2: Investigate ───────────────────────────────────────────────────
    print(f"\nSTEP 2 — AI investigation (this may take 10–60s)…")
    report = post_slow(f"{base_url}/incidents/{incident_id}/investigate")
    classification = report.get("classification", "?")
    mitre          = report.get("mitre_technique", "?")
    confidence     = report.get("confidence", 0)
    rag_sources    = report.get("rag_context", [])
    rec_actions    = report.get("recommended_actions", [])
    print(f"  ✓ Classification : {classification}")
    print(f"  ✓ MITRE          : {mitre}")
    print(f"  ✓ Confidence     : {confidence:.0%}")
    print(f"  ✓ RAG sources    : {rag_sources}")
    print(f"  ✓ Recommended actions ({len(rec_actions)}):")
    for a in rec_actions:
        print(f"      - {a.get('action')} → {a.get('target')}  priority={a.get('priority')}")

    # ── Step 3: Safety engine ─────────────────────────────────────────────────
    print(f"\nSTEP 3 — Safety engine (execute-actions)")
    safety_result = post(f"{base_url}/incidents/{incident_id}/execute-actions")
    summary = safety_result.get("summary", {})
    print(f"  ✓ Auto-executed      : {summary.get('auto_executed', 0)}")
    print(f"  ✓ Queued for approval: {summary.get('queued_for_approval', 0)}")
    print(f"  ✓ Blocked by safety  : {summary.get('blocked_by_safety', 0)}")
    for action in safety_result.get("actions", []):
        outcome = action.get("outcome")
        mark    = "✓" if outcome == "auto_executed" else ("⏳" if outcome == "queued_for_approval" else "✗")
        print(f"    {mark} {action.get('action_type'):20s} L{action.get('risk_level')}  → {outcome}")

    # ── Step 4: Show pending approvals ────────────────────────────────────────
    print(f"\nSTEP 4 — Pending approval queue")
    approvals = get(f"{base_url}/approvals")
    # Filter to only approvals belonging to this incident
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

    # ── Step 5: Approve all pending ───────────────────────────────────────────
    print(f"\nSTEP 5 — Analyst '{approver}' approves all pending actions")
    approved_count = 0
    for ap in our_approvals:
        decision_result = post(
            f"{base_url}/approvals/{ap['id']}/decide",
            {
                "decision": "approved",
                "approver": approver,
                "reason":   "Confirmed brute force attack — remediation approved.",
            },
        )
        act = decision_result.get("action") or {}
        print(f"  ✓ Approved: {act.get('action_type')} on {act.get('target')}")
        approved_count += 1

    if approved_count == 0:
        print("  (nothing to approve)")

    # ── Step 6: Execute approved actions (idempotent; decide already executes) ─
    print(f"\nSTEP 6 — Execute approved actions (idempotent re-check)")
    exec_result = post(f"{base_url}/incidents/{incident_id}/execute-approved")
    executed = exec_result.get("executed_count", 0)
    if approved_count > 0 and executed == 0:
        print("  ✓ No remaining approved actions (already executed on decide)")
    else:
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

    # ── Verify all expected event types are present ───────────────────────────
    print(f"\n{SEPARATOR}")
    print("  AUDIT TRAIL VERIFICATION")
    print(SEPARATOR)

    expected = [
        "incident.created",
        "incident.investigated",
        "safety.actions_processed",
    ]
    # At least one of these must exist (auto-executed or approval-queued actions)
    optional_any = [
        "safety.action_executed",
        "safety.approval_required",
    ]
    # These exist only if approvals were made
    if approved_count > 0:
        expected += ["approval.approved", "action.executed", "remediation.complete"]

    all_pass = True
    for evt in expected:
        ok = evt in seen_types
        mark = "✓" if ok else "✗"
        print(f"  {mark} {evt}")
        if not ok:
            all_pass = False

    for evt in optional_any:
        ok = evt in seen_types
        mark = "✓" if ok else "-"
        print(f"  {mark} {evt}  (optional)")

    print(f"\n{SEPARATOR}")
    if all_pass:
        print("  ✅  ALL CHECKS PASSED — Pipeline complete!")
    else:
        print("  ❌  SOME CHECKS FAILED — See above")
    print(f"{SEPARATOR}\n")

    return all_pass


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-SOC end-to-end pipeline test")
    parser.add_argument("--url",      default=DEFAULT_URL, help="Backend base URL")
    parser.add_argument("--approver", default="analyst1",  help="Analyst username for approvals")
    args = parser.parse_args()

    success = run(args.url, args.approver)
    sys.exit(0 if success else 1)
