"""SQLite persistence: incidents, blocklist, notifications, owners, audit log, settings, users."""
import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, pw_hash TEXT, role TEXT, created REAL);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, src_ip TEXT, dst_ip TEXT, threat_type TEXT,
  severity INTEGER, confidence REAL, anomaly_score REAL, count INTEGER DEFAULT 1,
  status TEXT DEFAULT 'open', actions TEXT, trace TEXT, intel TEXT, owner TEXT, true_label TEXT,
  response_ms REAL, notified INTEGER DEFAULT 0, updated REAL, pending TEXT);
CREATE TABLE IF NOT EXISTS blocklist(
  ip TEXT PRIMARY KEY, kind TEXT, reason TEXT, ts REAL, expires REAL, incident_id INTEGER, by TEXT);
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, incident_id INTEGER, owner TEXT, to_addr TEXT,
  subject TEXT, message TEXT, written_by TEXT, channels TEXT);
CREATE TABLE IF NOT EXISTS owners(
  prefix TEXT PRIMARY KEY, name TEXT, email TEXT, criticality INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS ix_inc_ts ON incidents(ts DESC);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts DESC);
"""


class DB:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur.lastrowid

    # settings stored as JSON values
    def get_setting(self, key, default=None):
        row = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def set_setting(self, key, value):
        self.x("INSERT INTO settings(key,value) VALUES(?,?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))

    def audit(self, actor, action, target="", detail=""):
        self.x("INSERT INTO audit(ts,actor,action,target,detail) VALUES(?,?,?,?,?)",
               (time.time(), actor, action, str(target), str(detail)))
