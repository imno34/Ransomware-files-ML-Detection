from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from software.config import ScoringConfig
from software.models import (
    ClassificationResult,
    PredictedClass,
    ProcessProfile,
    ThreatLevel,
)
from software.scoring import (
    ProcessSuspicionScorer,
    calculate_score,
    threat_level_for_score,
)
from software.tests.helpers import NOW, make_event


def base_profile(**changes) -> ProcessProfile:
    profile = ProcessProfile(
        process_id=1,
        process_name="sample.exe",
        process_start_time=NOW,
        process_key="1:test",
        first_seen=NOW,
        last_seen=NOW,
        window_start=NOW,
        window_size=30,
    )
    return replace(profile, **changes)


class ScoreRulesTests(unittest.TestCase):
    def test_all_documented_thresholds_are_applied(self):
        cases = [
            (
                {"ransomware_encrypted_count": 3},
                [
                    "ransomware_encrypted_count>=1",
                    "ransomware_encrypted_count>=2",
                    "ransomware_encrypted_count>=3",
                ],
            ),
            (
                {
                    "ransomware_ratio": 0.8,
                    "classified_events_count": 3,
                },
                ["ransomware_ratio>=0.5", "ransomware_ratio>=0.8"],
            ),
            (
                {"consecutive_ransomware_hits": 3},
                [
                    "consecutive_ransomware_hits>=2",
                    "consecutive_ransomware_hits>=3",
                ],
            ),
            (
                {"max_ransomware_probability": 0.95},
                [
                    "max_ransomware_probability>=0.92",
                    "max_ransomware_probability>=0.95",
                ],
            ),
            (
                {
                    "avg_ransomware_probability": 0.8,
                    "classified_events_count": 3,
                },
                [
                    "avg_ransomware_probability>=0.6",
                    "avg_ransomware_probability>=0.8",
                ],
            ),
            (
                {"events_in_window": 20},
                [
                    "events_in_window>=5",
                    "events_in_window>=10",
                    "events_in_window>=20",
                ],
            ),
            (
                {"touched_files_unique": 10},
                [
                    "touched_files_unique>=3",
                    "touched_files_unique>=5",
                    "touched_files_unique>=10",
                ],
            ),
            (
                {
                    "ransomware_encrypted_count": 2,
                    "touched_files_unique": 5,
                },
                [
                    "ransomware_encrypted_count>=1 and touched_files_unique>=5",
                    "ransomware_encrypted_count>=2 and touched_files_unique>=5",
                ],
            ),
        ]
        for values, expected_reasons in cases:
            with self.subTest(values=values):
                _score, reasons = calculate_score(base_profile(**values))
                joined = "; ".join(reasons)
                for reason in expected_reasons:
                    self.assertIn(reason, joined)

    def test_score_is_capped_at_100(self):
        score, _reasons = calculate_score(
            base_profile(
                ransomware_encrypted_count=10,
                classified_events_count=10,
                ransomware_ratio=1.0,
                consecutive_ransomware_hits=10,
                max_ransomware_probability=1.0,
                avg_ransomware_probability=1.0,
                events_in_window=30,
                touched_files_unique=30,
            )
        )
        self.assertEqual(score, 100)

    def test_threat_boundaries(self):
        expected = {
            0: ThreatLevel.LOW,
            29: ThreatLevel.LOW,
            30: ThreatLevel.MEDIUM,
            59: ThreatLevel.MEDIUM,
            60: ThreatLevel.HIGH,
            79: ThreatLevel.HIGH,
            80: ThreatLevel.CRITICAL,
            100: ThreatLevel.CRITICAL,
        }
        for score, level in expected.items():
            with self.subTest(score=score):
                self.assertEqual(threat_level_for_score(score), level)

    def test_consecutive_hits_recomputed_in_timestamp_order_and_window(self):
        scorer = ProcessSuspicionScorer(ScoringConfig(window_seconds=30))
        path = Path(tempfile.gettempdir()) / "sample.bin"
        late = make_event(
            path,
            event_id="late",
            timestamp=NOW + timedelta(seconds=2),
        )
        early = make_event(path, event_id="early", timestamp=NOW)
        middle = make_event(
            path,
            event_id="middle",
            timestamp=NOW + timedelta(seconds=1),
        )
        for event, predicted in (
            (late, PredictedClass.RANSOMWARE_ENCRYPTED),
            (early, PredictedClass.BENIGN),
            (middle, PredictedClass.RANSOMWARE_ENCRYPTED),
        ):
            event.classification_result = ClassificationResult(
                predicted_class=predicted,
                benign_probability=0.05,
                benign_encrypted_probability=0.05,
                ransomware_encrypted_probability=0.9,
                classifier_version="test",
            )
            profile = scorer.update_profile(event)
        self.assertEqual(profile.consecutive_ransomware_hits, 2)

        future = make_event(
            path,
            event_id="future",
            timestamp=NOW + timedelta(seconds=40),
        )
        future.classification_result = ClassificationResult(
            predicted_class=PredictedClass.BENIGN,
            benign_probability=0.9,
            benign_encrypted_probability=0.05,
            ransomware_encrypted_probability=0.05,
            classifier_version="test",
        )
        profile = scorer.update_profile(future)
        self.assertEqual(profile.events_in_window, 1)
        self.assertEqual(profile.consecutive_ransomware_hits, 0)


if __name__ == "__main__":
    unittest.main()
