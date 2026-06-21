from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from software.models import (
    ClassificationResult,
    PredictedClass,
    ProcessingStatus,
)
from software.pipeline import RuntimePipeline
from software.tests.helpers import make_config, make_event, make_small_bundle


class FakeExtractor:
    def extract(self, event):
        event.features = {"value": 1.0}
        event.features_ref = f"fake:{event.event_id}:features"
        event.extraction_status = ProcessingStatus.SUCCESS
        return event


class FakeVectorizer:
    def vectorize(self, event):
        event.feature_vector = [1.0]
        event.feature_vector_ref = f"fake:{event.event_id}:vector"
        event.vectorization_status = ProcessingStatus.SUCCESS
        return event


class FakeClassifier:
    def classify(self, event):
        event.classification_result = ClassificationResult(
            predicted_class=PredictedClass.RANSOMWARE_ENCRYPTED,
            benign_probability=0.01,
            benign_encrypted_probability=0.04,
            ransomware_encrypted_probability=0.95,
            classifier_version="integration-test",
        )
        return event


class FailingExtractor:
    def extract(self, event):
        event.extraction_status = ProcessingStatus.FAILED
        event.extraction_error = "synthetic extraction failure"
        return event


class RuntimePipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_pipeline_persists_event_profile_and_passive_response(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "sample.bin"
            path.write_bytes(b"payload")
            config = make_config(root)
            pipeline = RuntimePipeline(
                config,
                make_small_bundle(),
                extractor=FakeExtractor(),
                vectorizer=FakeVectorizer(),
                classifier=FakeClassifier(),
            )
            event = make_event(path)
            await pipeline.start()
            try:
                await pipeline.submit(event)
                await pipeline.join()
                stored_event = pipeline.storage.get_event(event.event_id)
                stored_profile = pipeline.storage.get_process(event.process_key)
                self.assertIsNotNone(stored_event)
                self.assertEqual(
                    stored_event["predicted_class"], "ransomware-encrypted"
                )
                self.assertEqual(stored_event["requested_action"], "warn")
                self.assertEqual(stored_event["executed_action"], "log")
                self.assertIsNotNone(stored_profile)
                self.assertEqual(stored_profile["suspicion_score"], 40)
                self.assertEqual(pipeline.storage.count_events(), 1)
            finally:
                await pipeline.stop()

    async def test_extraction_failure_is_persisted_and_stops_ml_processing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "sample.bin"
            path.write_bytes(b"payload")
            config = make_config(root, workers=1)
            pipeline = RuntimePipeline(
                config,
                make_small_bundle(),
                extractor=FailingExtractor(),
                vectorizer=FakeVectorizer(),
                classifier=FakeClassifier(),
            )
            event = make_event(path)
            await pipeline.start()
            try:
                await pipeline.submit(event)
                await pipeline.join()
                stored_event = pipeline.storage.get_event(event.event_id)
                self.assertEqual(stored_event["extraction_status"], "failed")
                self.assertEqual(stored_event["vectorization_status"], "skipped")
                self.assertIsNone(stored_event["predicted_class"])
                self.assertIsNone(
                    pipeline.storage.get_process(event.process_key)
                )
            finally:
                await pipeline.stop()


if __name__ == "__main__":
    unittest.main()
