"""
H¹¹-CGA Log Telemetry Adapter
===============================

Parses structured and unstructured log lines (Syslog, SSH auth.log, Auditd,
JSON audit trails) into normalized 11-dimensional SecurityEvent objects.
"""

from __future__ import annotations

import json
import logging
import re
import time
import threading
from collections import deque
from typing import Dict, Any, List, Optional

import numpy as np

from h11_cga.adapters.base import BaseTelemetryAdapter
from h11_cga.types import (
    TelemetryInput,
    SecurityEvent,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
    DIMENSION_INDEX,
)

logger = logging.getLogger(__name__)


class LogAdapter(BaseTelemetryAdapter):
    """
    Log Telemetry Adapter.

    Parses raw log strings or JSON audit objects (Auth failures, sudo escalations,
    auditd file access, kernel OOMs) and translates them into H¹¹ SecurityEvents.
    """

    def __init__(self, polling_interval: float = 1.0, max_pending: int = 10000) -> None:
        super().__init__(name="LogTelemetryAdapter", polling_interval=polling_interval)
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) or max_pending < 1:
            raise ValueError("max_pending must be a positive integer")
        self._pending_events = deque(maxlen=max_pending)
        self._pending_lock = threading.Lock()
        self.dropped_events = 0

        # Precompiled regex log patterns
        self._patterns = [
            (
                re.compile(r"Failed password for", re.IGNORECASE),
                "ssh_auth_failure",
                [0, 1],  # Identity, Authorization
                np.array([-0.2, -0.3, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                0.6,
            ),
            (
                re.compile(r"ACCEPTED password|session opened for user root", re.IGNORECASE),
                "root_session_opened",
                [1, 8],  # Authorization, Trust
                np.array([0, -0.1, 0, 0, 0, 0, 0, 0, -0.1, 0, 0]),
                0.4,
            ),
            (
                re.compile(r"Out of memory: Kill process", re.IGNORECASE),
                "kernel_oom_killer",
                [4, 5, 6],  # Compute, Memory, Execution
                np.array([0, 0, 0, 0, -0.3, -0.5, -0.4, 0, 0, 0, 0]),
                0.85,
            ),
            (
                re.compile(r"Segmentation fault|segfault", re.IGNORECASE),
                "process_segfault",
                [5, 6],  # Memory, Execution
                np.array([0, 0, 0, 0, 0, -0.3, -0.3, 0, 0, 0, 0]),
                0.7,
            ),
            (
                re.compile(r"unauthorized|permission denied|access forbidden", re.IGNORECASE),
                "access_denied_event",
                [1, 3],  # Authorization, Data
                np.array([0, -0.2, 0, -0.2, 0, 0, 0, 0, 0, 0, 0]),
                0.5,
            ),
        ]

    def _enqueue(self, event: SecurityEvent) -> None:
        with self._pending_lock:
            if len(self._pending_events) == self._pending_events.maxlen:
                self.dropped_events += 1
            self._pending_events.append(event)


    def parse_log_line(self, line: str) -> Optional[SecurityEvent]:
        """
        Parse a single log string into a SecurityEvent if a pattern matches.

        Args:
            line: Raw log string (e.g. from /var/log/auth.log).

        Returns:
            SecurityEvent if matched, None otherwise.
        """
        now = time.time()
        for pattern, event_type, target_dims, impact, severity in self._patterns:
            if pattern.search(line):
                event = SecurityEvent(
                    event_type=event_type,
                    source=self.name,
                    target_dimensions=target_dims,
                    impact=impact.copy(),
                    severity=severity,
                    metadata={"log_raw": line.strip()},
                    timestamp=now,
                )
                self._enqueue(event)
                logger.debug(f"Matched log event {event_type} from line: {line.strip()[:60]}")
                return event
        return None

    def ingest_json_log(self, json_data: str | Dict[str, Any]) -> Optional[SecurityEvent]:
        """
        Ingest structured JSON audit trail.

        Args:
            json_data: JSON string or dict.
        """
        if isinstance(json_data, str):
            try:
                data = json.loads(json_data)
            except Exception as err:
                logger.error(f"Failed to parse JSON log: {err}")
                return None
        else:
            data = json_data

        if not isinstance(data, dict):
            return None
        if any(not isinstance(data.get(key, ""), str) for key in ("action", "status", "event_type")):
            return None
        severity = data.get("severity", 0.6)
        if isinstance(severity, bool) or not isinstance(severity, (int, float)) or not np.isfinite(severity) or not 0 <= severity <= 1:
            return None
        now = time.time()
        event_type = data.get("event_type", "json_audit_event")
        action = data.get("action", "").lower()
        status = data.get("status", "").lower()

        impact = np.zeros(NUM_DIMENSIONS)
        target_dims = []

        if status in ("failed", "denied", "unauthorized", "403", "401"):
            impact[1] = -0.3  # Authorization
            impact[8] = -0.2  # Trust
            target_dims = [1, 8]
        elif action in ("privilege_escalation", "sudo_root"):
            impact[1] = -0.4  # Authorization
            impact[6] = -0.3  # Execution
            target_dims = [1, 6]

        if target_dims:
            event = SecurityEvent(
                event_type=event_type,
                source=self.name,
                target_dimensions=target_dims,
                impact=impact,
                severity=data.get("severity", 0.6),
                metadata=data,
                timestamp=now,
            )
            self._enqueue(event)
            return event

        return None

    def collect(self) -> TelemetryInput:
        """Return pending events and default baseline telemetry."""
        now = time.time()
        with self._pending_lock:
            events_to_return = list(self._pending_events)
            self._pending_events.clear()

        return TelemetryInput(
            raw_values={},
            events=events_to_return,
            timestamp=now,
        )
