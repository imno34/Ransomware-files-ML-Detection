from __future__ import annotations

import numpy as np

from .bundle import RuntimeBundle
from .models import ClassificationResult, FileEvent, PredictedClass
from .vectorizer import FeatureVectorizer


class FileClassifier:
    def __init__(self, bundle: RuntimeBundle, vectorizer: FeatureVectorizer):
        self.bundle = bundle
        self.vectorizer = vectorizer
        self._inverse_label_map = {
            int(value): PredictedClass(key)
            for key, value in self.bundle.label_map.items()
        }

    def classify(self, event: FileEvent) -> FileEvent:
        model_input = self.vectorizer.as_model_frame(event)
        predicted_id = int(np.asarray(self.bundle.model.predict(model_input))[0])
        raw_probabilities = np.asarray(
            self.bundle.model.predict_proba(model_input), dtype=np.float64
        )[0]
        probabilities = {label: 0.0 for label in self._inverse_label_map}
        for index, class_id in enumerate(self.bundle.model.classes_):
            probabilities[int(class_id)] = float(raw_probabilities[index])
        event.classification_result = ClassificationResult(
            predicted_class=self._inverse_label_map[predicted_id],
            benign_probability=probabilities[
                self.bundle.label_map[PredictedClass.BENIGN.value]
            ],
            benign_encrypted_probability=probabilities[
                self.bundle.label_map[PredictedClass.BENIGN_ENCRYPTED.value]
            ],
            ransomware_encrypted_probability=probabilities[
                self.bundle.label_map[PredictedClass.RANSOMWARE_ENCRYPTED.value]
            ],
            classifier_version=self.bundle.model_version,
        )
        return event
