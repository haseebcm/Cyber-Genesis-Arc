"""Durable SQLite response journal. Write intent before changing the OS."""
from __future__ import annotations
import json
import sqlite3
import threading
import time
from pathlib import Path


class AuditStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), timeout=10, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS responses (
                id TEXT PRIMARY KEY, pid INTEGER NOT NULL, created REAL NOT NULL,
                deadline REAL NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS watchdogs (id TEXT PRIMARY KEY, ready REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
                kind TEXT NOT NULL, payload TEXT NOT NULL
            );
        ''')
        self.db.commit()

    def event(self, kind, payload):
        with self.lock, self.db:
            self.db.execute('INSERT INTO events(timestamp,kind,payload) VALUES(?,?,?)',
                            (time.time(), kind, json.dumps(payload, allow_nan=False)))

    def prepare(self, action_id, pid, created, deadline, reason):
        with self.lock, self.db:
            self.db.execute('INSERT INTO responses VALUES(?,?,?,?,?,?)',
                            (action_id, pid, created, deadline, 'PENDING', reason))
            self.db.execute('INSERT INTO events(timestamp,kind,payload) VALUES(?,?,?)',
                            (time.time(), 'quarantine_intent', json.dumps({'id': action_id, 'pid': pid, 'reason': reason})))

    def watchdog_ready(self, action_id):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO watchdogs VALUES(?,?)', (action_id, time.time()))

    def has_watchdog(self, action_id):
        with self.lock:
            return self.db.execute('SELECT 1 FROM watchdogs WHERE id=?', (action_id,)).fetchone() is not None

    def set_deadline(self, action_id, deadline):
        with self.lock, self.db:
            self.db.execute('UPDATE responses SET deadline=? WHERE id=?', (deadline, action_id))

    def transition(self, action_id, state, detail=''):
        with self.lock, self.db:
            self.db.execute('UPDATE responses SET state=? WHERE id=?', (state, action_id))
            self.db.execute('INSERT INTO events(timestamp,kind,payload) VALUES(?,?,?)',
                            (time.time(), state.lower(), json.dumps({'id': action_id, 'detail': detail})))

    def get(self, action_id):
        with self.lock:
            row = self.db.execute('SELECT * FROM responses WHERE id=?', (action_id,)).fetchone()
            return dict(row) if row else None

    def active(self):
        with self.lock:
            return [dict(row) for row in self.db.execute("SELECT * FROM responses WHERE state IN ('PENDING','SUSPENDED','RECOVERY_FAILED')")]

    def recent(self, limit=100):
        with self.lock:
            return [dict(row) for row in self.db.execute('SELECT * FROM events ORDER BY seq DESC LIMIT ?', (min(max(int(limit), 1), 500),))]

    def close(self):
        with self.lock:
            self.db.close()
