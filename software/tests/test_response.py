from __future__ import annotations

import unittest
from unittest.mock import patch

from software.models import ResponseAction, ThreatLevel
from software.response import ResponseManager
from software.tests.test_scoring import base_profile


class ResponseManagerTests(unittest.TestCase):
    @patch("psutil.Process")
    def test_response_is_always_log_only(self, process_mock):
        manager = ResponseManager()
        for level, requested in (
            (ThreatLevel.LOW, ResponseAction.LOG),
            (ThreatLevel.MEDIUM, ResponseAction.WARN),
            (ThreatLevel.HIGH, ResponseAction.SUSPEND),
            (ThreatLevel.CRITICAL, ResponseAction.TERMINATE),
        ):
            with self.subTest(level=level):
                result = manager.handle(base_profile(threat_level=level))
                self.assertEqual(result.requested_action, requested)
                self.assertEqual(result.executed_action, ResponseAction.LOG)
        process_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
