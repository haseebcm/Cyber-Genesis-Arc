"""
H¹¹-CGA Control Plane REST API & Web Dashboard Server
======================================================

Lightweight HTTP/REST Control Plane Server serving live CGA telemetry status,
attack injection endpoints, domain control APIs, and the embedded SOC Dashboard.
"""

from __future__ import annotations

import json
import hmac
import math
import threading
from collections import deque
import logging
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, Any, Optional

import numpy as np

from h11_cga import (
    CyberGenesisEngine,
    TelemetryIngestionHub,
    SystemAdapter,
    EBPFNetworkProbe,
    CGAConfig,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
)
from h11_cga.license import LicenseManager, LicenseTier

logger = logging.getLogger(__name__)


# Global shared instances for server handler
_ENGINE_INSTANCE: Optional[CyberGenesisEngine] = None
_HUB_INSTANCE: Optional[TelemetryIngestionHub] = None
_LICENSE_INSTANCE: Optional[LicenseManager] = None


def get_shared_engine() -> CyberGenesisEngine:
    global _ENGINE_INSTANCE
    if _ENGINE_INSTANCE is None:
        _ENGINE_INSTANCE = CyberGenesisEngine()
    return _ENGINE_INSTANCE


def get_shared_hub() -> TelemetryIngestionHub:
    global _HUB_INSTANCE
    if _HUB_INSTANCE is None:
        _HUB_INSTANCE = TelemetryIngestionHub()
        # Register standard host OS & eBPF network probe adapters
        _HUB_INSTANCE.register_adapter(SystemAdapter())
        _HUB_INSTANCE.register_adapter(EBPFNetworkProbe())
    return _HUB_INSTANCE


def get_shared_license() -> LicenseManager:
    global _LICENSE_INSTANCE
    if _LICENSE_INSTANCE is None:
        _LICENSE_INSTANCE = LicenseManager(tier=LicenseTier.COMMUNITY_OPEN_CORE)
    return _LICENSE_INSTANCE


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads."""
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()



class ControlPlaneHTTPHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler for H¹¹-CGA Control Plane REST API.
    """

    def setup(self):
        super().setup()
        self.connection.settimeout(5.0)

    def _authorized(self):
        token = self.server.runtime.api_token
        if token and not hmac.compare_digest(self.headers.get("Authorization", "").encode("utf-8"), ("Bearer " + token).encode("utf-8")):
            self._send_json({"error": "Authentication required"}, 401)
            return False
        return True

    def _send_json(self, data: Dict[str, Any], status_code: int = 200) -> None:
        """Helper to return JSON response."""
        body = json.dumps(_json_safe(data), indent=2, allow_nan=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_content: str, status_code: int = 200) -> None:
        """Helper to return HTML response."""
        body = html_content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        with self.server.runtime.lock:
            self._get_snapshot()

    def _get_snapshot(self) -> None:
        """Handle HTTP GET requests."""
        runtime = self.server.runtime
        engine, hub, lic = runtime.engine, runtime.hub, runtime.license

        path = self.path.split("?")[0]

        if path == "/readyz":
            ready = runtime.assessment is not None and not runtime.engine.is_calibrating and not runtime.last_error and time.monotonic() - runtime.last_sample < runtime.interval * 3
            self._send_json({"ready": bool(ready)}, 200 if ready else 503)
            return
        if path == "/healthz":
            self._send_json({"status": "ok", "mode": runtime.mode})
            return
        if path.startswith("/api/") and not self._authorized():
            return

        if path == "/" or path == "/dashboard":
            # Serve embedded static SOC Web Dashboard UI
            html_path = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")
            if os.path.exists(html_path):
                with open(html_path, "r", encoding="utf-8") as f:
                    self._send_html(f.read())
            else:
                self._send_html("<h1>H¹¹-CGA SOC Dashboard UI file missing</h1>", status_code=404)

        elif path == "/api/v1/status":
            # Process tick with current telemetry
            assessment = runtime.assessment
            if assessment is None:
                self._send_json({"status": "STARTING"}, 503)
                return

            actions = [
                {
                    "urgency": a.urgency.value,
                    "action_type": a.action_type.value,
                    "target": a.target,
                    "dcr_score": round(a.dcr_score, 4),
                }
                for a in assessment.recommended_actions
            ]

            from h11_cga.core.advanced import StateIntegrityProver
            prover = runtime.prover
            signature = prover.sign_state(assessment.current_state)

            data = {
                "tick": runtime.tick,
                "mode": runtime.mode,
                "calibrating": engine.is_calibrating,
                "response_enforcement": "simulation" if runtime.demo else "recommendations_only",
                "telemetry_provenance": hub.last_provenance,
                "telemetry_skipped": hub.last_skipped,
                "status": assessment.status.value,
                "genesis_value": float(assessment.genesis_value),
                "dr_value": float(assessment.dr_value),
                "dr_adjusted": float(assessment.dr_adjusted),
                "hsa_coordinate": float(assessment.hsa_coordinate),
                "hsa_zone": assessment.hsa_zone.value,
                "security_buffer": float(assessment.security_buffer),
                "cci_value": float(assessment.cci_value),
                "permission": float(assessment.permission),
                "encrypt_classification": assessment.encrypt_classification.value,
                "domain_metric": float(assessment.domain_metric),
                "coherence": float(assessment.coherence),
                "permission_debt": float(assessment.permission_debt),
                "origin_hypotheses": [
                    {
                        "dimension": h.name,
                        "score": round(h.score, 4),
                        "explains": round(h.explained_fraction, 4),
                    }
                    for h in assessment.origin_hypotheses
                ],
                "origin_flux": float(assessment.origin_flux),
                "origin_defined": bool(assessment.origin_defined),
                "sovereign_signature": float(assessment.sovereign_signature),
                "law_conformance": (
                    {
                        "phi_h11": float(assessment.law_conformance.phi_h11),
                        "mean_conformance": float(
                            assessment.law_conformance.mean_conformance
                        ),
                        "sovereign": assessment.law_conformance.sovereign,
                        "laws": [
                            {
                                "law": law.law,
                                "name": law.name,
                                "measured": round(float(law.measured), 4),
                                "required": float(law.required),
                                "conformance": round(float(law.conformance), 4),
                                "verdict": law.verdict.value,
                            }
                            for law in assessment.law_conformance.laws
                        ],
                    }
                    if assessment.law_conformance
                    else None
                ),
                "nullification_cost": [
                    float(x) for x in assessment.nullification_cost
                ],
                "unexplained_vector": [
                    float(x) for x in assessment.unexplained_vector
                ],
                "state_vector": [float(x) for x in assessment.current_state.vector],
                "dimension_names": list(DIMENSION_NAMES),
                "recommended_actions": actions,
                "state_signature": signature,
                "state_timestamp": assessment.current_state.timestamp,
                "timestamp": assessment.timestamp,
            }
            self._send_json(data)

        elif path == "/api/v1/license":
            self._send_json(lic.get_tier_info())

        elif path == "/api/v1/adapters":
            self._send_json({"registered_adapters": hub.registered_adapters})

        else:
            self._send_json({"error": "Endpoint not found", "path": path}, status_code=404)

    def do_POST(self):
        runtime = self.server.runtime
        if not self._authorized():
            return
        if not runtime.demo:
            self._send_json({"error": "Simulation controls are disabled in monitor mode"}, 403)
            return
        if self.headers.get("Origin"):
            self._send_json({"error": "Cross-origin mutations are disabled"}, 403)
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self._send_json({"error": "application/json required"}, 415)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 16384:
                self._send_json({"error": "Request body must contain 1–16384 bytes"}, 413)
                return
            payload = json.loads(self.rfile.read(length), parse_constant=lambda x: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
            if not isinstance(payload, dict):
                raise ValueError("JSON object required")
            path = self.path.split("?")[0]
            with runtime.lock:
                if path == "/api/v1/attack":
                    if set(payload) - {"attack", "severity"}:
                        raise ValueError("Unexpected fields")
                    attack = payload.get("attack", "identity_compromise")
                    severity = payload.get("severity", 0.5)
                    if isinstance(severity, bool) or not isinstance(severity, (int, float)):
                        raise ValueError("Numeric severity required")
                    assessment = runtime.engine.inject_attack(attack, severity)
                    message = "Simulated attack injected"
                elif path == "/api/v1/self-heal":
                    if payload:
                        raise ValueError("Empty object required")
                    from h11_cga.core.advanced import SelfHealingProjector
                    engine = runtime.engine
                    restored, _, _ = SelfHealingProjector(engine._config).project_to_permissible_manifold(engine._sense.get_current_state(), engine._sense.get_baseline())
                    engine._sense.current_state = restored
                    assessment = engine.process_tick()
                    message = "Simulation state projected; no host remediation performed"
                else:
                    self._send_json({"error": "Endpoint not found"}, 404)
                    return
                runtime.publish(assessment)
                runtime.audit.append({"timestamp": time.time(), "path": path, "status": assessment.status.value})
                logger.info("simulation_mutation path=%s status=%s", path, assessment.status.value)
            self._send_json({"message": message, "new_status": assessment.status.value, "genesis_value": assessment.genesis_value})
        except (ValueError, TypeError, UnicodeError):
            self._send_json({"error": "Invalid request payload"}, 400)
        except TimeoutError:
            self._send_json({"error": "Request timed out"}, 408)


def _json_safe(value):
    """Undefined model quantities are JSON null, never nonstandard NaN/Infinity."""
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (float, np.floating)) and not math.isfinite(value):
        return None
    return value


class Runtime:
    def __init__(self, demo=False, api_token=None, interval=1.0):
        from h11_cga.core.advanced import StateIntegrityProver
        self.demo, self.api_token, self.interval = demo, api_token, interval
        self.mode = "simulation" if demo else "monitor"
        self.engine = CyberGenesisEngine(CGAConfig(baseline_calibration_ticks=0 if demo else 20))
        self.hub = TelemetryIngestionHub()
        if not demo:
            self.hub.register_adapter(SystemAdapter())
            self.hub.register_adapter(EBPFNetworkProbe())
        self.license = LicenseManager(tier=LicenseTier.COMMUNITY_OPEN_CORE)
        self.prover = StateIntegrityProver()
        self.lock = threading.RLock()
        self.audit = deque(maxlen=1000)
        self.assessment = None
        self.tick = 0
        self.last_sample = 0.0
        self.last_error = False
        self.stop_event = threading.Event()

    def publish(self, assessment):
        self.tick = self.engine.get_dashboard()["tick"]
        self.assessment = assessment
        self.last_sample = time.monotonic()
        self.last_error = False

    def sample(self):
        with self.lock:
            self.publish(self.engine.process_tick(None if self.demo else self.hub.collect_all()))

    def run(self):
        while not self.stop_event.wait(self.interval):
            try:
                self.sample()
            except Exception:
                self.last_error = True
                logger.exception("Telemetry cycle failed")


class ControlPlaneServer:
    """Local-first monitoring service; remote binds require bearer authentication."""
    def __init__(self, host="127.0.0.1", port=8080, *, demo=False, api_token=None, interval=1.0):
        api_token = api_token or os.environ.get("H11_API_TOKEN")
        if host not in {"127.0.0.1", "localhost", "::1"} and not api_token:
            raise ValueError("Remote binding requires H11_API_TOKEN")
        if api_token is not None and len(api_token) < 32:
            raise ValueError("API token must contain at least 32 characters")
        if not math.isfinite(interval) or interval < 0.05:
            raise ValueError("Sampling interval must be at least 0.05 seconds")
        self.host, self.port = host, port
        self.runtime = Runtime(demo, api_token, interval)
        self._server = None
        self._worker = None

    def start(self):
        self._server = ThreadedHTTPServer((self.host, self.port), ControlPlaneHTTPHandler)
        self.port = self._server.server_address[1]
        self._server.runtime = self.runtime
        self.runtime.sample()
        self._worker = threading.Thread(target=self.runtime.run, daemon=True)
        self._worker.start()
        logger.info("Control plane listening on %s:%s (%s)", self.host, self.port, self.runtime.mode)
        try:
            self._server.serve_forever()
        finally:
            self.runtime.stop_event.set()
            self._server.server_close()
            if self._worker:
                self._worker.join(timeout=5)
            for name in self.runtime.hub.registered_adapters:
                self.runtime.hub.unregister_adapter(name)

    def stop(self):
        self.runtime.stop_event.set()
        if self._server:
            self._server.shutdown()
