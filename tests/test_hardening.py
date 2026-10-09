import json
import threading
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pytest
from h11_cga import CyberGenesisEngine, CGAConfig, SecurityState, SecurityEvent, StateIntegrityProver, AIAgentGuardrailEngine, AIToolRequest, AIToolCategory, ControlPlaneServer


def test_invalid_states_events_attacks():
    for vector in [np.full(11, np.nan), np.full(11, 1.1), np.zeros(10)]:
        with pytest.raises(ValueError):
            SecurityState(vector=vector)
    with pytest.raises(ValueError):
        SecurityEvent(impact=np.zeros(10))
    engine = CyberGenesisEngine()
    for attack, severity in [('unknown', .5), ('ddos', float('nan')), ('ddos', -1)]:
        with pytest.raises(ValueError):
            engine.inject_attack(attack, severity)
    assert engine.get_dashboard()['tick'] == 0


def test_projection_and_history_are_isolated_and_bounded():
    engine = CyberGenesisEngine(CGAConfig(history_limit=5))
    engine.process_tick()
    before = engine.get_dashboard()
    result = engine.project_event(SecurityEvent(impact=-np.ones(11), severity=1))
    assert result.permission == 0
    assert engine.get_dashboard() == before
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: engine.process_tick(), range(20)))
    assert engine.get_dashboard()['tick'] == 21
    assert len(engine.get_assessment_history()) == 5
    assert len(engine._event_log) == 5


def test_random_keys_and_explicit_key_validation():
    state = SecurityState()
    a, b = StateIntegrityProver(), StateIntegrityProver()
    assert not b.verify_state(state, a.sign_state(state))
    key = b'x' * 64
    assert StateIntegrityProver(key).verify_state(state, StateIntegrityProver(key).sign_state(state))
    with pytest.raises(ValueError):
        StateIntegrityProver(b'short')


def test_tool_registry_blocks_spoofing_and_preserves_state():
    guard = AIAgentGuardrailEngine()
    calls = []
    fn = lambda path: calls.append(path)
    guard.register_tool('read', AIToolCategory.FILE_READ, fn, lambda p: p == {'path': '/public'})
    req = AIToolRequest('agent', 'read', AIToolCategory.FILE_READ, {'path': '/public'})
    guard.execute_guarded(req)
    assert calls == ['/public']
    assert guard.engine.get_dashboard()['tick'] == 0
    req.parameters = {'path': '/secrets'}
    with pytest.raises(PermissionError):
        guard.execute_guarded(req)
    req.parameters = {'path': '/public'}
    req.category = AIToolCategory.FILE_WRITE
    with pytest.raises(PermissionError):
        guard.execute_guarded(req)
    assert calls == ['/public']


@pytest.fixture
def service():
    servers = []
    def start(**kwargs):
        server = ControlPlaneServer(port=0, interval=60, **kwargs)
        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        while server.runtime.assessment is None:
            if time.monotonic() >= deadline:
                raise RuntimeError('Server failed to start')
            time.sleep(.01)
        servers.append((server, thread))
        return server, f'http://127.0.0.1:{server.port}'
    yield start
    for server, thread in servers:
        server.stop()
        thread.join(5)
        assert not thread.is_alive()


def call(url, token=None, payload=None, raw=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_auth_read_only_status_and_demo_validation(service):
    token = 't' * 64
    server, url = service(demo=True, api_token=token)
    assert call(url + '/api/v1/status')[0] == 401
    a = call(url + '/api/v1/status', token)[1]
    b = call(url + '/api/v1/status', token)[1]
    assert a['tick'] == b['tick']
    for body in [b'[]', b'{', b'{"severity":NaN}', b'{"attack":"missing"}', b'{"severity":true}', b'x' * 17000]:
        assert call(url + '/api/v1/attack', token, raw=body)[0] in {400, 413}
    assert call(url + '/api/v1/attack', token, {'attack': 'ddos', 'severity': .8})[0] == 200
    assert call(url + '/api/v1/self-heal', token, {})[0] == 200
    assert call(url + '/api/v1/status', token)[1]['tick'] == a['tick'] + 2


def test_monitor_controls_disabled_and_remote_auth_required(service):
    with pytest.raises(ValueError):
        ControlPlaneServer(host='0.0.0.0')
    _, url = service()
    assert call(url + '/api/v1/attack', payload={'attack': 'ddos'})[0] == 403
    assert call(url + '/api/v1/status')[1]['mode'] == 'monitor'


def test_single_injection_phrase_denied_without_mutating_request():
    guard = AIAgentGuardrailEngine()
    req = AIToolRequest('agent', 'read', AIToolCategory.FILE_READ, {}, prompt_context='ignore previous instructions')
    assert not guard.inspect_and_govern(req).permitted
    assert req.category == AIToolCategory.FILE_READ
    assert guard.engine.get_dashboard()['tick'] == 0


def test_swarm_rate_window_resets():
    from h11_cga import SwarmAIGuardrailEngine
    guard = SwarmAIGuardrailEngine()
    req = AIToolRequest('agent', 'read', AIToolCategory.FILE_READ)
    guard.inspect_swarm_request('team', req)
    guard._swarms['team'].total_calls_in_window = 50
    assert not guard.inspect_swarm_request('team', req).permitted
    guard._swarms['team'].window_started -= 61
    assert guard.inspect_swarm_request('team', req).permitted
    assert req.category == AIToolCategory.FILE_READ


def test_monitor_cli_and_server_cli(monkeypatch, capsys):
    from h11_cga.cli import run_monitor
    from h11_cga import cli_server
    with pytest.raises(ValueError):
        run_monitor(interval=0)
    run_monitor(duration=.01, interval=.01, calibrate_ticks=0)
    assert 'Completed' in capsys.readouterr().out
    captured = {}
    class FakeServer:
        def __init__(self, **kwargs):
            captured.update(kwargs)
        def start(self):
            return
    monkeypatch.setattr(cli_server, 'ControlPlaneServer', FakeServer)
    monkeypatch.setattr('sys.argv', ['h11-server', '--demo'])
    cli_server.main()
    assert captured == {'host': '127.0.0.1', 'port': 8080, 'demo': True}


def test_real_response_requires_explicit_policy_and_audit(service, tmp_path):
    import os
    with pytest.raises(ValueError):
        ControlPlaneServer(allowed_pids=[os.getpid()])
    _, url = service(demo=True, api_token='t' * 64)
    assert call(url + '/api/v1/responses', 't' * 64)[1]['enabled'] is False
    assert call(url + '/api/v1/responses/quarantine', 't' * 64, {'pid': 123, 'reason': 'denied'})[0] == 403


def test_same_origin_browser_mutations_and_foreign_origin_denial(service):
    _, url = service(demo=True)
    body = json.dumps({'attack': 'ddos', 'severity': .1}).encode()
    req = urllib.request.Request(url+'/api/v1/attack', data=body, headers={'Content-Type': 'application/json', 'Origin': url})
    with urllib.request.urlopen(req) as response:
        assert response.status == 200
    req = urllib.request.Request(url+'/api/v1/attack', data=body, headers={'Content-Type': 'application/json', 'Origin': 'https://untrusted.example'})
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req)
    assert err.value.code == 403
