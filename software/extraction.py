from __future__ import annotations

from threading import Lock

from featurizers.extract import ExtractContext, extract_feats, load_cfg

from .models import FileEvent, ProcessingStatus


class FeatureExtractor:
    def __init__(self, *, fallback: bool = True):
        self.cfg = load_cfg()
        self.context = ExtractContext(self.cfg)
        self.fallback = fallback
        self._lock = Lock()

    def extract(self, event: FileEvent) -> FileEvent:
        try:
            with self._lock:
                features = extract_feats(
                    event.file_path,
                    self.cfg,
                    context=self.context,
                    fallback=self.fallback,
                )
            event.features = features
            event.features_ref = f"sqlite:file_events/{event.event_id}#features_json"
            event.extraction_status = ProcessingStatus.SUCCESS
            event.extraction_error = None
        except Exception as exc:
            event.features = None
            event.extraction_status = ProcessingStatus.FAILED
            event.extraction_error = f"{type(exc).__name__}: {exc}"
        return event
