"""Real operating-system integration tests: only disposable test children."""
import os
import subprocess
import sys
import time
import psutil
import pytest
from h11_cga.response import ProcessResponseController, AuditStore


@pytest.fixture
def child():
    try:
        psutil.Process().create_time()
    except psutil.NoSuchProcess:
        pytest.skip("Host procfs does not match the execution PID namespace")
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])
    time.sleep(.1)
    try:
        yield process
    finally:
        try:
            psutil.Process(process.pid).resume()
        except psutil.Error:
            pass
        process.terminate()
        process.wait(timeout=10)


def test_real_suspend_resume_idempotency_and_durable_journal(tmp_path, child):
    controller = ProcessResponseController([child.pid], tmp_path/'audit.sqlite3', 3)
    try:
        response = controller.quarantine(child.pid, 'integration test', 2)
        assert response['state'] == 'SUSPENDED'
        assert psutil.Process(child.pid).status() == psutil.STATUS_STOPPED
        assert controller.quarantine(child.pid, 'retry')['id'] == response['id']
        assert controller.resume(response['id'])['state'] == 'RESUMED'
        assert controller.resume(response['id'])['state'] == 'RESUMED'
        assert psutil.Process(child.pid).status() != psutil.STATUS_STOPPED
    finally:
        controller.close()
    journal = AuditStore(tmp_path/'audit.sqlite3')
    assert any(row['kind'] == 'resumed' for row in journal.recent())
    assert not journal.active()
    journal.close()


def test_watchdog_rolls_back_real_suspension(tmp_path, child):
    controller = ProcessResponseController([child.pid], tmp_path/'audit.sqlite3', 1)
    try:
        response = controller.quarantine(child.pid, 'timeout test')
        deadline = time.monotonic() + 5
        while controller.audit.get(response['id'])['state'] != 'RESUMED':
            assert time.monotonic() < deadline
            time.sleep(.05)
        assert psutil.Process(child.pid).status() != psutil.STATUS_STOPPED
    finally:
        controller.close()


def test_policy_denies_self_unknown_pid_and_invalid_hold(tmp_path, child):
    with pytest.raises(ValueError):
        ProcessResponseController([os.getpid()], tmp_path/'self.sqlite3')
    controller = ProcessResponseController([child.pid], tmp_path/'audit.sqlite3', 2)
    try:
        with pytest.raises(PermissionError):
            controller.quarantine(os.getpid(), 'denied')
        with pytest.raises(ValueError):
            controller.quarantine(child.pid, 'denied', 3)
        assert psutil.Process(child.pid).status() != psutil.STATUS_STOPPED
    finally:
        controller.close()


def test_restart_recovers_pending_intent(tmp_path, child):
    path = tmp_path/'audit.sqlite3'
    journal = AuditStore(path)
    journal.prepare('crash-test', child.pid, psutil.Process(child.pid).create_time(), time.time()+30, 'restart')
    psutil.Process(child.pid).suspend()
    journal.close()
    controller = ProcessResponseController([child.pid], path)
    try:
        assert psutil.Process(child.pid).status() != psutil.STATUS_STOPPED
        assert controller.audit.get('crash-test')['state'] == 'RESUMED'
    finally:
        controller.close()


def test_recycled_identity_is_never_resumed(tmp_path, child):
    path = tmp_path/'audit.sqlite3'
    journal = AuditStore(path)
    journal.prepare('stale', child.pid, psutil.Process(child.pid).create_time()-100, time.time()+1, 'stale')
    journal.close()
    controller = ProcessResponseController([child.pid], path)
    try:
        assert controller.audit.get('stale')['state'] == 'EXITED'
    finally:
        controller.close()


def test_detached_watchdog_survives_service_crash(tmp_path, child):
    path = tmp_path/'crash.sqlite3'
    code = '''import os,sys,time
from h11_cga.response import ProcessResponseController
c=ProcessResponseController([int(sys.argv[1])],sys.argv[2],2)
c.quarantine(int(sys.argv[1]),'crash rollback')
os._exit(0)
'''
    subprocess.run([sys.executable, '-c', code, str(child.pid), str(path)], check=True, timeout=10)
    deadline = time.monotonic() + 12
    while psutil.Process(child.pid).status() == psutil.STATUS_STOPPED:
        assert time.monotonic() < deadline
        time.sleep(.1)
    journal = AuditStore(path)
    assert not journal.active()
    journal.close()


def test_authenticated_real_response_api(tmp_path, child):
    import json
    import threading
    import urllib.request
    from h11_cga import ControlPlaneServer
    token = 't'*64
    service = ControlPlaneServer(port=0, api_token=token, allowed_pids=[child.pid], audit_path=tmp_path/'api.sqlite3')
    thread = threading.Thread(target=service.start, daemon=True)
    thread.start()
    deadline = time.monotonic()+5
    while service.runtime.assessment is None:
        assert time.monotonic()<deadline
        time.sleep(.02)
    base = f'http://127.0.0.1:{service.port}'
    def request(path, payload):
        req = urllib.request.Request(base+path, data=json.dumps(payload).encode(), headers={'Content-Type':'application/json','Authorization':'Bearer '+token,'Origin':base})
        with urllib.request.urlopen(req) as response:
            return json.load(response)
    try:
        result = request('/api/v1/responses/quarantine', {'pid':child.pid,'reason':'API integration','hold_seconds':2})
        assert result['state']=='SUSPENDED'
        assert psutil.Process(child.pid).status()==psutil.STATUS_STOPPED
        assert request('/api/v1/responses/resume', {'response_id':result['id']})['state']=='RESUMED'
    finally:
        service.stop()
        thread.join(timeout=5)
