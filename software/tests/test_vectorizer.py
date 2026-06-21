from __future__ import annotations

import math
import tempfile
import unittest
from pathlib import Path

import numpy as np

from software.bundle import RuntimeBundle
from software.models import ProcessingStatus
from software.tests.helpers import DummyModel, make_event
from software.vectorizer import FeatureVectorizer


class AddTenScaler:
    def transform(self, values):
        return np.asarray(values, dtype=np.float64) + 10.0


class FeatureVectorizerTests(unittest.TestCase):
    def test_golden_single_file_vectorization(self):
        bundle = RuntimeBundle(
            model=DummyModel(),
            feature_list=("byte_chi2", "flag", "pdf_version"),
            dtype_map={
                "byte_chi2": "float",
                "flag": "bool",
                "pdf_version": "float",
            },
            fill_values={
                "byte_chi2": 0.0,
                "flag": False,
                "pdf_version": 0.0,
            },
            scaler=AddTenScaler(),
            scaler_columns=("byte_chi2",),
            label_map={
                "benign": 0,
                "benign-encrypted": 1,
                "ransomware-encrypted": 2,
            },
            model_version="golden",
            feature_schema_hash="test-only",
        )
        event = make_event(Path(tempfile.gettempdir()) / "sample.pdf")
        event.features = {
            "byte_chi2": 3.0,
            "flag": None,
            "pdf_version": None,
        }
        FeatureVectorizer(bundle).vectorize(event)
        self.assertEqual(event.vectorization_status, ProcessingStatus.SUCCESS)
        self.assertEqual(len(event.feature_vector), 3)
        self.assertAlmostEqual(event.feature_vector[0], math.log1p(3.0) + 10.0)
        self.assertEqual(event.feature_vector[1:], [0.0, 0.0])

    def test_missing_fill_value_causes_failure(self):
        bundle = RuntimeBundle(
            model=DummyModel(),
            feature_list=("value",),
            dtype_map={"value": "float"},
            fill_values={},
            scaler=AddTenScaler(),
            scaler_columns=(),
            label_map={
                "benign": 0,
                "benign-encrypted": 1,
                "ransomware-encrypted": 2,
            },
            model_version="broken",
            feature_schema_hash="test-only",
        )
        event = make_event(Path(tempfile.gettempdir()) / "sample.pdf")
        event.features = {"value": None}
        FeatureVectorizer(bundle).vectorize(event)
        self.assertEqual(event.vectorization_status, ProcessingStatus.FAILED)
        self.assertIn("unfilled values", event.vectorization_error)


if __name__ == "__main__":
    unittest.main()
