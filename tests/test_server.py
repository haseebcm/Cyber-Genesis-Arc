"""
H¹¹-CGA Phase 4 Server & License Unit Tests
=============================================
Tests for ControlPlaneServer HTTP endpoints and LicenseManager.
"""

import json
import threading
import time
import urllib.request
import pytest

from h11_cga import (
    ControlPlaneServer,
    LicenseManager,
    LicenseTier,
    FeatureFlag,
)


@pytest.fixture(scope="module")
def test_server():
    server = ControlPlaneServer(host="127.0.0.1", port=8888, demo=True)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    time.sleep(1.0)
    yield server
    server.stop()
    thread.join(timeout=5)


def test_license_manager():
    mgr_open = LicenseManager(tier=LicenseTier.COMMUNITY_OPEN_CORE)
    assert mgr_open.is_feature_enabled(FeatureFlag.CORE_MATH_ENGINE) is True
    assert mgr_open.is_feature_enabled(FeatureFlag.REST_API_SERVER) is True
    assert mgr_open.is_feature_enabled(FeatureFlag.HARDWARE_ENCRYPT_IC_KERNEL) is False

    mgr_ent = LicenseManager(tier=LicenseTier.ENTERPRISE)
    assert mgr_ent.is_feature_enabled(FeatureFlag.HARDWARE_ENCRYPT_IC_KERNEL) is True


def test_server_status_endpoint(test_server):
    req = urllib.request.urlopen("http://127.0.0.1:8888/api/v1/status")
    assert req.status == 200

    data = json.loads(req.read().decode("utf-8"))
    assert "status" in data
    assert "genesis_value" in data
    assert "state_vector" in data
    assert len(data["state_vector"]) == 11


def test_server_license_endpoint(test_server):
    req = urllib.request.urlopen("http://127.0.0.1:8888/api/v1/license")
    assert req.status == 200

    data = json.loads(req.read().decode("utf-8"))
    assert data["tier"] == "COMMUNITY_OPEN_CORE"


def test_server_attack_post_endpoint(test_server):
    payload = json.dumps({"attack": "ddos", "severity": 0.8}).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8888/api/v1/attack",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    res = urllib.request.urlopen(req)
    assert res.status == 200

    data = json.loads(res.read().decode("utf-8"))
    assert "message" in data
    assert "new_status" in data


def test_server_dashboard_html_endpoint(test_server):
    req = urllib.request.urlopen("http://127.0.0.1:8888/")
    assert req.status == 200
    html = req.read().decode("utf-8")
    assert "H¹¹ CYBER GENESIS COMMAND CENTER" in html or "H11 CYBER GENESIS COMMAND CENTER" in html
