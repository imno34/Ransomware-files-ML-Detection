from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from threading import RLock

from .config import ScoringConfig
from .models import (
    FileEvent,
    PredictedClass,
    ProcessProfile,
    ProfileStatus,
    ThreatLevel,
)


class ProcessSuspicionScorer:
    def __init__(self, config: ScoringConfig):
        self.config = config
        self._events: dict[str, list[FileEvent]] = defaultdict(list)
        self._lock = RLock()

    def update_profile(self, event: FileEvent) -> ProcessProfile:
        with self._lock:
            events = self._events[event.process_key]
            if all(existing.event_id != event.event_id for existing in events):
                events.append(event)
            events.sort(key=lambda item: (item.timestamp, item.event_id))
            reference_time = events[-1].timestamp
            cutoff = reference_time - timedelta(seconds=self.config.window_seconds)
            events[:] = [item for item in events if item.timestamp >= cutoff]
            profile = self._build_profile(events)
            score, reasons = calculate_score(profile)
            profile.suspicion_score = score
            profile.threat_level = threat_level_for_score(score)
            profile.decision_reason = "; ".join(reasons) or "no scoring rules matched"
            return profile

    def expire_before(self, timestamp) -> list[ProcessProfile]:
        expired: list[ProcessProfile] = []
        with self._lock:
            cutoff = timestamp - timedelta(seconds=self.config.window_seconds)
            for process_key in list(self._events):
                events = self._events[process_key]
                if not events or events[-1].timestamp >= cutoff:
                    continue
                profile = self._build_profile(events)
                profile.profile_status = ProfileStatus.EXPIRED
                expired.append(profile)
                del self._events[process_key]
        return expired

    def _build_profile(self, events: list[FileEvent]) -> ProcessProfile:
        if not events:
            raise ValueError("cannot build a process profile without events")
        ordered = sorted(events, key=lambda item: (item.timestamp, item.event_id))
        latest = ordered[-1]
        classified = [
            item for item in ordered if item.classification_result is not None
        ]
        predictions = [
            item.classification_result.predicted_class for item in classified
        ]
        ransomware_probabilities = [
            item.classification_result.ransomware_encrypted_probability
            for item in classified
        ]
        consecutive = 0
        for predicted in reversed(predictions):
            if predicted != PredictedClass.RANSOMWARE_ENCRYPTED:
                break
            consecutive += 1
        ransomware_count = predictions.count(PredictedClass.RANSOMWARE_ENCRYPTED)
        classified_count = len(classified)
        touched_paths = [item.file_path for item in ordered if item.file_path]
        return ProcessProfile(
            process_id=latest.process_id,
            process_name=latest.process_name,
            process_start_time=latest.process_start_time,
            process_key=latest.process_key,
            first_seen=ordered[0].timestamp,
            last_seen=latest.timestamp,
            window_start=max(
                ordered[0].timestamp,
                latest.timestamp - timedelta(seconds=self.config.window_seconds),
            ),
            window_size=self.config.window_seconds,
            events_in_window=len(ordered),
            classified_events_count=classified_count,
            benign_count=predictions.count(PredictedClass.BENIGN),
            benign_encrypted_count=predictions.count(
                PredictedClass.BENIGN_ENCRYPTED
            ),
            ransomware_encrypted_count=ransomware_count,
            consecutive_ransomware_hits=consecutive,
            ransomware_ratio=(
                ransomware_count / classified_count if classified_count else 0.0
            ),
            max_ransomware_probability=(
                max(ransomware_probabilities) if ransomware_probabilities else 0.0
            ),
            avg_ransomware_probability=(
                sum(ransomware_probabilities) / len(ransomware_probabilities)
                if ransomware_probabilities
                else 0.0
            ),
            touched_files=len(touched_paths),
            touched_files_unique=len(set(touched_paths)),
            last_event_id=latest.event_id,
        )


def calculate_score(profile: ProcessProfile) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    def add(condition: bool, points: int, reason: str) -> None:
        nonlocal score
        if condition:
            score += points
            reasons.append(f"{reason} (+{points})")

    count = profile.ransomware_encrypted_count
    add(count >= 1, 25, "ransomware_encrypted_count>=1")
    add(count >= 2, 20, "ransomware_encrypted_count>=2")
    add(count >= 3, 15, "ransomware_encrypted_count>=3")

    add(
        profile.ransomware_ratio >= 0.5
        and profile.classified_events_count >= 2,
        20,
        "ransomware_ratio>=0.5 and classified_events_count>=2",
    )
    add(
        profile.ransomware_ratio >= 0.8
        and profile.classified_events_count >= 3,
        15,
        "ransomware_ratio>=0.8 and classified_events_count>=3",
    )

    add(
        profile.consecutive_ransomware_hits >= 2,
        15,
        "consecutive_ransomware_hits>=2",
    )
    add(
        profile.consecutive_ransomware_hits >= 3,
        15,
        "consecutive_ransomware_hits>=3",
    )

    add(
        profile.max_ransomware_probability >= 0.92,
        5,
        "max_ransomware_probability>=0.92",
    )
    add(
        profile.max_ransomware_probability >= 0.95,
        10,
        "max_ransomware_probability>=0.95",
    )

    add(
        profile.avg_ransomware_probability >= 0.6
        and profile.classified_events_count >= 2,
        10,
        "avg_ransomware_probability>=0.6 and classified_events_count>=2",
    )
    add(
        profile.avg_ransomware_probability >= 0.8
        and profile.classified_events_count >= 3,
        15,
        "avg_ransomware_probability>=0.8 and classified_events_count>=3",
    )

    add(profile.events_in_window >= 5, 10, "events_in_window>=5")
    add(profile.events_in_window >= 10, 10, "events_in_window>=10")
    add(profile.events_in_window >= 20, 15, "events_in_window>=20")

    add(profile.touched_files_unique >= 3, 10, "touched_files_unique>=3")
    add(profile.touched_files_unique >= 5, 10, "touched_files_unique>=5")
    add(profile.touched_files_unique >= 10, 15, "touched_files_unique>=10")

    add(
        count >= 1 and profile.touched_files_unique >= 5,
        15,
        "ransomware_encrypted_count>=1 and touched_files_unique>=5",
    )
    add(
        count >= 2 and profile.touched_files_unique >= 5,
        15,
        "ransomware_encrypted_count>=2 and touched_files_unique>=5",
    )

    return min(100, score), reasons


def threat_level_for_score(score: int) -> ThreatLevel:
    if score < 0 or score > 100:
        raise ValueError("suspicion score must be in range 0..100")
    if score < 30:
        return ThreatLevel.LOW
    if score < 60:
        return ThreatLevel.MEDIUM
    if score < 80:
        return ThreatLevel.HIGH
    return ThreatLevel.CRITICAL
