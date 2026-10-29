"""
API contract regression tests (TestClient + dependency overrides).

Uses an in-memory SQLite stand-in where possible; skips if SQLAlchemy models
require PostgreSQL-only types that SQLite cannot create.
"""

import os
import unittest
from unittest.mock import patch

# Ensure telemetry stays off during tests
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")


class PaginationContractTests(unittest.TestCase):
    """Backend list_incidents must honour `skip`, not a phantom `offset`."""

    def test_list_incidents_signature_uses_skip(self):
        import inspect
        from routers.incidents import list_incidents

        params = inspect.signature(list_incidents).parameters
        self.assertIn("skip", params)
        self.assertNotIn("offset", params)
        self.assertIn("limit", params)


class CorsContractTests(unittest.TestCase):
    def test_cors_allows_vite_dev_origin(self):
        from main import app

        cors_mw = None
        for middleware in app.user_middleware:
            if middleware.cls.__name__ == "CORSMiddleware":
                cors_mw = middleware
                break
        self.assertIsNotNone(cors_mw)
        origins = cors_mw.kwargs.get("allow_origins", [])
        self.assertIn("http://localhost:5173", origins)
        self.assertIn("http://127.0.0.1:5173", origins)


class InvestigationResponseShapeTests(unittest.TestCase):
    def test_trigger_investigation_flattens_report_fields(self):
        """Router must expose classification at top level for e2e/clients."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from routers import investigation as inv_router

        fake_report = {
            "classification": "Brute Force Attack",
            "mitre_technique": "T1110",
            "confidence": 0.9,
            "recommended_actions": [],
            "investigation_failed": False,
        }

        with patch.object(
            inv_router,
            "investigate_incident",
            new=AsyncMock(return_value=fake_report),
        ):
            result = asyncio.run(
                inv_router.trigger_investigation("INC-1", db=MagicMock())
            )

        self.assertEqual(result["classification"], "Brute Force Attack")
        self.assertEqual(result["mitre_technique"], "T1110")
        self.assertEqual(result["incident_id"], "INC-1")
        self.assertEqual(result["status"], "investigation_complete")
        self.assertNotIn("report", result)  # not nested under "report"


if __name__ == "__main__":
    unittest.main()
