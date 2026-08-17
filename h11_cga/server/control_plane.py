"""
H¹¹-CGA Control Plane REST API & Web Dashboard Server
======================================================

Lightweight HTTP/REST Control Plane Server serving live CGA telemetry status,
attack injection endpoints, domain control APIs, and the embedded SOC Dashboard.
"""

from __future__ import annotations

import json
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


class ControlPlaneHTTPHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler for H¹¹-CGA Control Plane REST API.
    """

    def _send_json(self, data: Dict[str, Any], status_code: int = 200) -> None:
        """Helper to return JSON response."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
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

    def do_GET(self) -> None:
        """Handle HTTP GET requests."""
        engine = get_shared_engine()
        hub = get_shared_hub()
        lic = get_shared_license()

        path = self.path.split("?")[0]

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
            telemetry = hub.collect_all()
            assessment = engine.process_tick(telemetry)

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
            prover = StateIntegrityProver()
            signature = prover.sign_state(assessment.current_state)

            data = {
                "tick": engine.get_dashboard().get("tick", 0),
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
                "timestamp": time.time(),
            }
            self._send_json(data)

        elif path == "/api/v1/license":
            self._send_json(lic.get_tier_info())

        elif path == "/api/v1/adapters":
            self._send_json({"registered_adapters": hub.registered_adapters})

        else:
            self._send_json({"error": "Endpoint not found", "path": path}, status_code=404)

    def do_POST(self) -> None:
        """Handle HTTP POST requests."""
        engine = get_shared_engine()
        path = self.path.split("?")[0]

        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            payload = {}

        if path == "/api/v1/attack":
            attack_name = payload.get("attack", "identity_compromise")
            severity = float(payload.get("severity", 0.5))

            assessment = engine.inject_attack(attack_name, severity=severity)
            self._send_json({
                "message": f"Injected attack '{attack_name}' with severity {severity}.",
                "new_status": assessment.status.value,
                "genesis_value": float(assessment.genesis_value),
            })

        elif path == "/api/v1/self-heal":
            from h11_cga.core.advanced import SelfHealingProjector
            projector = SelfHealingProjector(engine._config)
            current = engine._sense.get_current_state()
            baseline = engine._sense.get_baseline()
            restored, energy, _ = projector.project_to_permissible_manifold(current, baseline)
            engine._sense.current_state = restored
            assessment = engine.process_tick()
            self._send_json({
                "message": f"Applied Self-Healing Projection R_genesis. Energy restored = {energy:.4f}",
                "energy_restored": energy,
                "new_status": assessment.status.value,
                "genesis_value": float(assessment.genesis_value),
            })

        else:
            self._send_json({"error": "Endpoint not found", "path": path}, status_code=404)


class ControlPlaneServer:
    """
    H¹¹-CGA Control Plane REST API Server Daemon.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        self.host = host
        self.port = port
        self._server: Optional[ThreadedHTTPServer] = None

    def start(self) -> None:
        """Start the Control Plane HTTP Server."""
        server_address = (self.host, self.port)
        self._server = ThreadedHTTPServer(server_address, ControlPlaneHTTPHandler)
        logger.info(f"H¹¹-CGA Control Plane Server running on http://{self.host}:{self.port}")
        print(f"\n  * H11-CGA Control Plane Server running on http://localhost:{self.port}")
        print(f"  * Open http://localhost:{self.port} in your browser for the Web Dashboard UI.\n")
        self._server.serve_forever()

    def stop(self) -> None:
        """Stop the Control Plane HTTP Server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            logger.info("H¹¹-CGA Control Plane Server stopped.")
