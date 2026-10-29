"""Regression tests for the deterministic policy engine."""

import unittest

from services.policy import (
    ACTION_RISK_LEVELS,
    derive_asset_criticality,
    derive_user_role,
    evaluate_action,
    get_risk_level,
)


class PolicyEngineTests(unittest.TestCase):
    def test_isolate_host_always_requires_approval(self):
        result = evaluate_action("isolate_host", {"asset_criticality": "medium"})
        self.assertEqual(result["decision"], "require_approval")
        self.assertIsNotNone(result["policy_id"])

    def test_disable_account_always_requires_approval(self):
        result = evaluate_action("disable_account", {"user_role": "user"})
        self.assertEqual(result["decision"], "require_approval")

    def test_shutdown_server_blocked(self):
        result = evaluate_action("shutdown_server", {})
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["policy_id"], "P003")

    def test_recover_before_forensics_blocked(self):
        result = evaluate_action("recover_system", {"forensic_complete": False})
        self.assertEqual(result["decision"], "block")

    def test_low_risk_actions_allowed_by_default(self):
        for action in ("collect_logs", "tag_ioc", "block_ip", "notify_analyst"):
            with self.subTest(action=action):
                result = evaluate_action(action, {})
                self.assertEqual(result["decision"], "allowed")
                self.assertIsNone(result["policy_id"])

    def test_risk_levels_match_safety_thresholds(self):
        self.assertLessEqual(ACTION_RISK_LEVELS["collect_logs"], 4)
        self.assertGreaterEqual(ACTION_RISK_LEVELS["kill_process"], 5)
        self.assertGreaterEqual(ACTION_RISK_LEVELS["disable_account"], 5)
        self.assertEqual(get_risk_level("shutdown_server"), 7)
        self.assertEqual(get_risk_level("unknown_action"), 3)

    def test_derive_helpers(self):
        self.assertEqual(derive_asset_criticality("web-server-02"), "critical")
        self.assertEqual(derive_asset_criticality("laptop-01"), "medium")
        self.assertEqual(derive_user_role("admin"), "administrator")
        self.assertEqual(derive_user_role("jdoe"), "user")


if __name__ == "__main__":
    unittest.main()
