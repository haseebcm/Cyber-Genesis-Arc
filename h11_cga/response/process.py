"""Cross-platform process quarantine with pinned identities and timed rollback.

This controller performs real psutil suspend/resume operations, not vector edits.
Only an operator-configured PID may be suspended. Recycled identities are refused.
"""
from __future__ import annotations
import math
import os
import threading
import time
import uuid
import subprocess
import sys
import psutil
from .audit import AuditStore


class ProcessResponseController:
    def __init__(self, allowed_pids, audit_path, max_hold_seconds=30):
        if not math.isfinite(max_hold_seconds) or not 1 <= max_hold_seconds <= 300:
            raise ValueError('Quarantine hold must be between 1 and 300 seconds')
        if len(allowed_pids) > 32:
            raise ValueError("At most 32 process targets may be configured")
        self.lock = threading.RLock()
        self.max_hold_seconds = max_hold_seconds
        self.allowed = {}
        self.audit = AuditStore(audit_path)
        for row in self.audit.active():
            self._resume_row(row, recovery=True)
        forbidden = {0, 1, os.getpid()}
        forbidden.update(p.pid for p in psutil.Process().parents())
        for pid in allowed_pids:
            if isinstance(pid, bool) or not isinstance(pid, int) or pid < 2 or pid in forbidden:
                raise ValueError('Cannot target the service, its ancestors, or system PID 1')
            process = psutil.Process(pid)
            # Refuse users other than the service account, even when elevated.
            if process.username() != psutil.Process().username():
                raise PermissionError('Only processes owned by the service account may be targeted')
            if process.status() == psutil.STATUS_STOPPED:
                raise ValueError('Refusing an already suspended process')
            self.allowed[pid] = process
        self.stop_event = threading.Event()
        self._closed = False
        self.last_error = None
        self.worker = threading.Thread(target=self._watchdog, daemon=True)
        self.worker.start()

    def _identity(self, pid, created):
        process = psutil.Process(pid)
        if process.create_time() != created or not process.is_running():
            raise psutil.NoSuchProcess(pid)
        if process.username() != psutil.Process().username():
            raise PermissionError('Process ownership changed')
        if pid in {0, 1, os.getpid()} or pid in {p.pid for p in psutil.Process().parents()}:
            raise PermissionError('Protected process')
        return process

    def quarantine(self, pid, reason, hold_seconds=None):
        with self.lock:
            if self._closed:
                raise RuntimeError('Response controller is closed')
            if isinstance(pid, bool) or not isinstance(pid, int) or pid not in self.allowed:
                raise PermissionError('PID is not explicitly permitted by operator policy')
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
                raise ValueError('A reason of 1–512 characters is required')
            hold = self.max_hold_seconds if hold_seconds is None else hold_seconds
            if isinstance(hold, bool) or not isinstance(hold, (int, float)) or not math.isfinite(hold) or not 1 <= hold <= self.max_hold_seconds:
                raise ValueError('Hold exceeds configured policy')
            existing = next((r for r in self.audit.active() if r['pid'] == pid), None)
            if existing:
                return existing
            pinned = self.allowed[pid]
            process = self._identity(pid, pinned.create_time())
            if process.status() == psutil.STATUS_STOPPED:
                raise PermissionError('Process was suspended outside this controller')
            action_id = uuid.uuid4().hex
            self.audit.prepare(action_id, pid, pinned.create_time(), time.time() + hold, reason)
            try:
                # psutil itself checks PID reuse before suspend/resume on both OSes.
                options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
                if os.name == "nt":
                    options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                else:
                    options["start_new_session"] = True
                # A separate recovery process survives abrupt service termination.
                subprocess.Popen([sys.executable, "-m", "h11_cga.response.recovery", str(self.audit.path.resolve()), action_id], **options)
                ready_deadline = time.monotonic() + 5
                while not self.audit.has_watchdog(action_id):
                    if time.monotonic() >= ready_deadline:
                        raise RuntimeError("Independent rollback watchdog did not start")
                    time.sleep(.02)
                self.audit.set_deadline(action_id, time.time() + hold)
                pinned.suspend()
                deadline = time.monotonic() + 2
                while pinned.status() != psutil.STATUS_STOPPED:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('OS did not confirm process suspension')
                    time.sleep(.01)
                self.audit.transition(action_id, 'SUSPENDED')
            except Exception:
                # Write-ahead intent permits retrying recovery if rollback fails.
                self._resume_row(self.audit.get(action_id), recovery=True)
                raise
            return self.audit.get(action_id)

    def resume(self, action_id):
        with self.lock:
            row = self.audit.get(action_id)
            if row is None:
                raise ValueError('Unknown response ID')
            if row['state'] in {'RESUMED', 'EXITED'}:
                return row
            self._resume_row(row)
            return self.audit.get(action_id)

    def _resume_row(self, row, recovery=False):
        with self.audit.lock:
            self.audit.db.execute("BEGIN IMMEDIATE")
            try:
                current = self.audit.get(row["id"])
                if not current or current["state"] not in {"PENDING", "SUSPENDED", "RECOVERY_FAILED"}:
                    return
                self._resume_locked(current, recovery)
            finally:
                self.audit.db.commit()

    def _resume_locked(self, row, recovery=False):
        try:
            process = self._identity(row['pid'], row['created'])
            process.resume()
            deadline = time.monotonic() + 2
            while process.status() == psutil.STATUS_STOPPED:
                if time.monotonic() >= deadline:
                    raise RuntimeError('OS did not confirm process resumption')
                time.sleep(.01)
            self.audit.transition(row['id'], 'RESUMED', 'restart/rollback' if recovery else 'operator/watchdog')
        except psutil.NoSuchProcess:
            self.audit.transition(row['id'], 'EXITED', 'original process exited; no recycled PID touched')
        except Exception as error:
            self.audit.transition(row['id'], 'RECOVERY_FAILED', type(error).__name__)
            if not recovery:
                raise

    def _watchdog(self):
        while not self.stop_event.wait(.2):
            try:
                with self.lock:
                    for row in self.audit.active():
                        if row['deadline'] <= time.time():
                            self._resume_row(row, recovery=True)
                    self.last_error = "rollback_failed" if any(r["state"] == "RECOVERY_FAILED" for r in self.audit.active()) else None
            except Exception as error:
                self.last_error = type(error).__name__

    def close(self):
        self.stop_event.set()
        self.worker.join(timeout=5)
        with self.lock:
            if self._closed:
                return
            for row in self.audit.active():
                self._resume_row(row, recovery=True)
            self.audit.close()
            self._closed = True
