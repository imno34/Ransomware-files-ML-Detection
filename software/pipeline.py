from __future__ import annotations

import asyncio
import logging
from typing import Any

from .bundle import RuntimeBundle
from .classifier import FileClassifier
from .config import RuntimeConfig
from .extraction import FeatureExtractor
from .filtering import EventPreFilter
from .models import (
    FileEvent,
    FilterDecision,
    ProcessingStatus,
    StabilizationStatus,
)
from .response import ResponseManager
from .scoring import ProcessSuspicionScorer
from .stabilizer import FileStabilizer
from .storage import RuntimeStorage
from .vectorizer import FeatureVectorizer


_STOP = object()


class RuntimePipeline:
    def __init__(
        self,
        config: RuntimeConfig,
        bundle: RuntimeBundle,
        *,
        storage: RuntimeStorage | None = None,
        event_filter: EventPreFilter | None = None,
        stabilizer: FileStabilizer | None = None,
        extractor: FeatureExtractor | None = None,
        vectorizer: FeatureVectorizer | None = None,
        classifier: FileClassifier | None = None,
        scorer: ProcessSuspicionScorer | None = None,
        response_manager: ResponseManager | None = None,
        logger: logging.Logger | None = None,
    ):
        self.config = config
        self.bundle = bundle
        self.storage = storage or RuntimeStorage(config.storage.path)
        self.event_filter = event_filter or EventPreFilter(
            config.filters, config.monitor
        )
        self.stabilizer = stabilizer or FileStabilizer(config.stabilization)
        self.extractor = extractor or FeatureExtractor(
            fallback=config.processing.extraction_fallback
        )
        self.vectorizer = vectorizer or FeatureVectorizer(bundle)
        self.classifier = classifier or FileClassifier(bundle, self.vectorizer)
        self.scorer = scorer or ProcessSuspicionScorer(config.scoring)
        self.response_manager = response_manager or ResponseManager()
        self.logger = logger or logging.getLogger("software.pipeline")
        self.queue: asyncio.Queue[Any] = asyncio.Queue(
            maxsize=config.processing.queue_size
        )
        self._workers: list[asyncio.Task] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False

    async def start(self) -> None:
        if self._workers:
            return
        self._loop = asyncio.get_running_loop()
        self._workers = [
            asyncio.create_task(self._worker(index), name=f"pipeline-worker-{index}")
            for index in range(self.config.processing.workers)
        ]

    async def submit(self, event: FileEvent) -> None:
        if not self._workers:
            raise RuntimeError("pipeline is not started")
        self.storage.save_event(event)
        self.logger.info(
            "event_received event_id=%s type=%s path=%s process_key=%s",
            event.event_id,
            event.event_type.value,
            event.file_path,
            event.process_key,
        )
        await self.queue.put(event)

    def submit_threadsafe(self, event: FileEvent) -> None:
        if self._loop is None:
            raise RuntimeError("pipeline is not started")
        self._loop.call_soon_threadsafe(self._submit_nowait, event)

    async def join(self) -> None:
        await self.queue.join()

    async def stop(self) -> None:
        if self._closed:
            return
        await self.queue.join()
        for _ in self._workers:
            await self.queue.put(_STOP)
        await asyncio.gather(*self._workers, return_exceptions=False)
        self._workers.clear()
        self.storage.close()
        self._closed = True

    async def process_event(self, event: FileEvent) -> FileEvent:
        self.event_filter.filter(event)
        self.storage.save_event(event)
        self.logger.debug(
            "event_filtered event_id=%s decision=%s reason=%s priority=%s",
            event.event_id,
            event.filter_decision.value,
            event.filter_reason,
            event.event_priority.value,
        )

        if event.filter_decision == FilterDecision.DROP:
            self._mark_skipped(event)
            self.storage.save_event(event)
            return event

        if event.filter_decision == FilterDecision.CONTEXT_ONLY:
            self._mark_skipped(event)
            return self._profile_and_respond(event)

        await self.stabilizer.stabilize(event)
        self.storage.save_event(event)
        if event.stabilization_status != StabilizationStatus.STABLE:
            event.extraction_status = ProcessingStatus.SKIPPED
            event.vectorization_status = ProcessingStatus.SKIPPED
            self.storage.save_event(event)
            return event

        await asyncio.to_thread(self.extractor.extract, event)
        self.storage.save_event(event)
        if event.extraction_status != ProcessingStatus.SUCCESS:
            event.vectorization_status = ProcessingStatus.SKIPPED
            self.storage.save_event(event)
            return event

        await asyncio.to_thread(self.vectorizer.vectorize, event)
        self.storage.save_event(event)
        if event.vectorization_status != ProcessingStatus.SUCCESS:
            return event

        try:
            await asyncio.to_thread(self.classifier.classify, event)
            event.classification_error = None
        except Exception as exc:
            event.classification_error = f"{type(exc).__name__}: {exc}"
            self.logger.exception(
                "Classification failed event_id=%s", event.event_id
            )
            self.storage.save_event(event)
            return event
        self.storage.save_event(event)
        return self._profile_and_respond(event)

    def _profile_and_respond(self, event: FileEvent) -> FileEvent:
        profile = self.scorer.update_profile(event)
        self.storage.save_process(profile)
        event.process_profile_ref = f"sqlite:processes/{profile.process_key}"
        self.storage.save_event(event)
        event.response_result = self.response_manager.handle(profile)
        self.storage.save_event(event)
        return event

    async def _worker(self, index: int) -> None:
        while True:
            item = await self.queue.get()
            try:
                if item is _STOP:
                    return
                await self.process_event(item)
            except Exception:
                self.logger.exception(
                    "Unhandled pipeline error worker=%s event=%r", index, item
                )
                if isinstance(item, FileEvent):
                    try:
                        self.storage.save_event(item)
                    except Exception:
                        self.logger.exception("Failed to persist errored event")
            finally:
                self.queue.task_done()

    def _mark_skipped(self, event: FileEvent) -> None:
        event.stabilization_status = StabilizationStatus.SKIPPED
        event.extraction_status = ProcessingStatus.SKIPPED
        event.vectorization_status = ProcessingStatus.SKIPPED

    def _submit_nowait(self, event: FileEvent) -> None:
        try:
            self.storage.save_event(event)
            self.queue.put_nowait(event)
            self.logger.info(
                "event_received event_id=%s type=%s path=%s process_key=%s",
                event.event_id,
                event.event_type.value,
                event.file_path,
                event.process_key,
            )
        except asyncio.QueueFull:
            event.filter_decision = FilterDecision.DROP
            event.filter_reason = "processing_queue_full"
            self._mark_skipped(event)
            self.storage.save_event(event)
            self.logger.error(
                "event_dropped_queue_full event_id=%s path=%s",
                event.event_id,
                event.file_path,
            )
        except Exception:
            self.logger.exception(
                "Failed to enqueue ETW event event_id=%s", event.event_id
            )
