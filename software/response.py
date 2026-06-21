from __future__ import annotations

import logging

from .models import (
    ProcessProfile,
    ResponseAction,
    ResponseResult,
    ResponseStatus,
    ThreatLevel,
)


class ResponseManager:
    """Passive response manager.

    It records the action that an enforcing deployment would request, but always
    executes LOG. No process-control API is called by this class.
    """

    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger("software.response")

    def handle(self, profile: ProcessProfile) -> ResponseResult:
        requested = self.select_action(profile)
        result = ResponseResult(
            response_action=requested,
            requested_action=requested,
            executed_action=ResponseAction.LOG,
            response_status=ResponseStatus.LOGGED,
        )
        self.logger.warning(
            "process_response process_key=%s pid=%s score=%s threat=%s "
            "requested=%s executed=log",
            profile.process_key,
            profile.process_id,
            profile.suspicion_score,
            profile.threat_level.value,
            requested.value,
        )
        return result

    @staticmethod
    def select_action(profile: ProcessProfile) -> ResponseAction:
        return {
            ThreatLevel.LOW: ResponseAction.LOG,
            ThreatLevel.MEDIUM: ResponseAction.WARN,
            ThreatLevel.HIGH: ResponseAction.SUSPEND,
            ThreatLevel.CRITICAL: ResponseAction.TERMINATE,
        }[profile.threat_level]
