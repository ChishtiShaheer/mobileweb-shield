"""Repository layer: parameterized SQLite + append-only, hash-chained audit log."""
import hashlib, json, sqlite3, threading, time, uuid
import bcrypt
from . import config

_lock = threading.Lock()

def conn():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA foreign_keys=ON")
    return c

def q(sql, params=(), one=False):
    with _lock, conn() as c:
        rows = [dict(r) for r in c.execute(sql, params).fetchall()]
    return (rows[0] if rows else None) if one else rows

def x(sql, params=()):
    with _lock, conn() as c:
        c.execute(sql, params)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash BLOB NOT NULL, role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, csrf TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id), ua_hash TEXT, ua TEXT, ip TEXT, created REAL, last_seen REAL,
  expires REAL, revoked_at REAL, revoke_reason TEXT);
CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), tag TEXT,
  iv TEXT NOT NULL, ct TEXT NOT NULL, version INTEGER NOT NULL, updated REAL);
CREATE TABLE IF NOT EXISTS ops(op_id TEXT, user_id TEXT, result TEXT, PRIMARY KEY(op_id, user_id));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, role TEXT, action TEXT,
  outcome TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
"""

def init_db():
    with _lock, conn() as c:
        c.executescript(SCHEMA)
    for k, v in config.DEFAULT_SETTINGS.items():
        x("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
    if not q("SELECT 1 FROM users LIMIT 1"):
        for role, (name, pw) in config.SEED.items():
            h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
            x("INSERT INTO users VALUES(?,?,?,?)", (str(uuid.uuid4()), name, h, role))

def reset_db():  # tests only
    if config.DB_PATH.exists():
        for s in ("", "-wal", "-shm"):
            p = config.DB_PATH.with_name(config.DB_PATH.name + s)
            if p.exists(): p.unlink()
    init_db()

def get_settings() -> dict:
    return {r["key"]: r["value"] for r in q("SELECT key,value FROM settings")}

SENSITIVE = {"password", "pw", "ct", "iv", "token", "csrf", "api_key"}
def _redact(d: dict) -> dict:
    return {k: ("[REDACTED]" if k in SENSITIVE else v) for k, v in (d or {}).items()}

def _digest(prev, ts, actor, action, outcome, detail):
    return hashlib.sha256(f"{prev}|{ts}|{actor}|{action}|{outcome}|{detail}".encode()).hexdigest()

def audit(actor, role, action, outcome="OK", detail=None):
    detail_s = json.dumps(_redact(detail), sort_keys=True, default=str)
    with _lock, conn() as c:
        last = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else "GENESIS"
        ts = round(time.time(), 3)
        c.execute("INSERT INTO audit(ts,actor,role,action,outcome,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
                  (ts, actor, role, action, outcome, detail_s, prev, _digest(prev, ts, actor, action, outcome, detail_s)))

def verify_audit_chain() -> dict:
    prev = "GENESIS"
    for r in q("SELECT * FROM audit ORDER BY id"):
        if r["prev_hash"] != prev or r["hash"] != _digest(prev, r["ts"], r["actor"], r["action"], r["outcome"], r["detail"]):
            return {"valid": False, "broken_at": r["id"]}
        prev = r["hash"]
    return {"valid": True, "broken_at": None}
