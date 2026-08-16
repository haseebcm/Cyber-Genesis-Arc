"""
H¹¹-CGA Phase 4 — Control Plane Server & Web Dashboard Demo
============================================================

Launches the H¹¹-CGA Control Plane REST API Server and embedded Web Dashboard UI,
testing API endpoints and demonstrating real-time browser control plane integration.
"""

import json
import threading
import time
import urllib.request

from h11_cga import ControlPlaneServer, LicenseManager, LicenseTier


def run_server_in_thread(port: int = 8080) -> ControlPlaneServer:
    server = ControlPlaneServer(host="127.0.0.1", port=port)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    time.sleep(1.0)  # Wait for server to bind port
    return server


def http_get(url: str) -> dict:
    req = urllib.request.urlopen(url)
    return json.loads(req.read().decode("utf-8"))


def http_post(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req)
    return json.loads(res.read().decode("utf-8"))


def main() -> None:
    port = 8080
    print("=" * 78)
    print("  H11-CGA PHASE 4 -- CONTROL PLANE SERVER & WEB DASHBOARD DEMONSTRATION")
    print("=" * 78)

    # 1. Start Server Daemon
    print(f"\nStarting H11 Control Plane HTTP Server on http://127.0.0.1:{port}...")
    server = run_server_in_thread(port=port)

    # 2. Query License Tier API Endpoint
    lic_data = http_get(f"http://127.0.0.1:{port}/api/v1/license")
    print("\n[GET /api/v1/license]:")
    print(f"  Licensee: {lic_data.get('licensee')}")
    print(f"  Tier:     {lic_data.get('tier')}")
    print(f"  Active Features ({lic_data.get('total_active_features')}): {', '.join(lic_data.get('features', [])[:4])}...")

    # 3. Query System Status API Endpoint
    status_data = http_get(f"http://127.0.0.1:{port}/api/v1/status")
    print("\n[GET /api/v1/status]:")
    print(f"  System Status:  {status_data.get('status')}")
    print(f"  Genesis Value:  {status_data.get('genesis_value'):+.4f}")
    print(f"  Divergence DR:  {status_data.get('dr_value'):.4f}")
    print(f"  HSA Singularity:{status_data.get('hsa_coordinate'):+.4f} [{status_data.get('hsa_zone')}]")

    # 4. Post Attack Injection via REST API
    print("\n[POST /api/v1/attack] Ingesting 'privilege_escalation' attack...")
    attack_res = http_post(f"http://127.0.0.1:{port}/api/v1/attack", {"attack": "privilege_escalation", "severity": 0.7})
    print(f"  Response: {attack_res.get('message')}")
    print(f"  New Status: {attack_res.get('new_status')} | G_c = {attack_res.get('genesis_value'):+.4f}")

    # 5. Modify Domain Activation via REST API
    print("\n[POST /api/v1/domain] Nullifying resource domain...")
    domain_res = http_post(f"http://127.0.0.1:{port}/api/v1/domain", {"dimension": "resource", "level": 0.0})
    print(f"  Response: {domain_res.get('message')}")

    print("\n" + "=" * 78)
    print(f"  * Web Dashboard UI Available at: http://localhost:{port}")
    print("  * Phase 4 Control Plane Server Demo complete.")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
