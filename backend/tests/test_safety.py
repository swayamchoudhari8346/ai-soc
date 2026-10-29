"""Regression tests for safety-engine approval/execution guards."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from services import safety


def _action(**kwargs):
    defaults = dict(
        id=1,
        incident_id="INC-TEST",
        action_type="disable_account",
        target="admin",
        risk_level=6,
        status="pending",
        policy_decision="require_approval",
        policy_reason="test",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class SafetyProcessSingleActionTests(unittest.TestCase):
    def test_policy_block_is_not_executed(self):
        action = _action(policy_decision="block", risk_level=4, action_type="block_ip")
        db = MagicMock()
        result = safety._process_single_action(action, db)
        self.assertEqual(result["outcome"], "policy_blocked")
        self.assertNotEqual(action.status, "executed")

    def test_l7_is_hard_blocked(self):
        action = _action(
            action_type="shutdown_server",
            risk_level=7,
            policy_decision="allowed",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = safety._process_single_action(action, db)
        self.assertEqual(result["outcome"], "blocked_by_safety")
        self.assertEqual(action.status, "blocked")

    def test_l5_queues_for_approval_not_auto_execute(self):
        action = _action(
            action_type="kill_process",
            risk_level=5,
            policy_decision="allowed",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = safety._process_single_action(action, db)
        self.assertEqual(result["outcome"], "queued_for_approval")
        self.assertEqual(action.status, "pending")

    def test_require_approval_policy_queues_even_at_l4(self):
        action = _action(
            action_type="isolate_host",
            risk_level=4,  # hypothetically low risk but policy says approve
            policy_decision="require_approval",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = safety._process_single_action(action, db)
        self.assertEqual(result["outcome"], "queued_for_approval")

    def test_l4_allowed_auto_executes_simulated(self):
        action = _action(
            action_type="collect_logs",
            risk_level=4,
            policy_decision="allowed",
        )
        db = MagicMock()
        result = safety._process_single_action(action, db)
        self.assertEqual(result["outcome"], "auto_executed")
        self.assertTrue(result.get("simulated"))
        self.assertEqual(action.status, "executed")


class ExecuteApprovedGuardsTests(unittest.TestCase):
    def test_refuses_without_approval_record(self):
        action = _action(status="approved", policy_decision="require_approval")
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [action]

        # First Action query returns [action]; Approval query returns None
        approval_query = MagicMock()
        approval_query.filter.return_value.first.return_value = None

        action_query = MagicMock()
        action_query.filter.return_value.all.return_value = [action]

        def query_side_effect(model):
            name = getattr(model, "__name__", str(model))
            if "Approval" in name or model is safety.Approval:
                return approval_query
            return action_query

        db.query.side_effect = query_side_effect

        import asyncio
        results = asyncio.run(safety.execute_approved_actions("INC-TEST", db))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["outcome"], "refused_missing_approval")
        self.assertNotEqual(action.status, "executed")

    def test_refuses_policy_block_even_if_status_approved(self):
        action = _action(
            status="approved",
            policy_decision="block",
            action_type="shutdown_server",
            risk_level=7,
        )
        db = MagicMock()

        action_query = MagicMock()
        action_query.filter.return_value.all.return_value = [action]
        db.query.return_value = action_query

        import asyncio
        results = asyncio.run(safety.execute_approved_actions("INC-TEST", db))
        self.assertEqual(results[0]["outcome"], "refused_policy_block")
        self.assertEqual(action.status, "blocked")


class JsonExtractTests(unittest.TestCase):
    def test_extract_json_rejects_garbage(self):
        from services.investigation import _extract_json
        with self.assertRaises(ValueError):
            _extract_json("sorry I cannot help with that")

    def test_extract_json_from_fenced_block(self):
        from services.investigation import _extract_json
        raw = '```json\n{"classification": "Brute Force Attack", "confidence": 0.9}\n```'
        data = _extract_json(raw)
        self.assertEqual(data["classification"], "Brute Force Attack")


if __name__ == "__main__":
    unittest.main()
