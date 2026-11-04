"""API/service layer: authn, authz, validation, safe errors. Security logic lives in security_engine."""
import csv, hashlib, io, json, secrets, time, uuid
from typing import List, Optional
import bcrypt
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from . import config, db, security_engine as eng
from .explain import explain_event

app = FastAPI(title="MobileWeb Shield API", docs_url=None, redoc_url=None, openapi_url=None)
limiter = eng.LoginLimiter()
DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt())

@app.on_event("startup")
def _startup(): db.init_db()

class ApiError(Exception):
    def __init__(self, status, code, msg, extra=None): self.status, self.code, self.msg, self.extra = status, code, msg, extra or {}

def err(status, code, msg, extra=None):
    return JSONResponse({"error": {"code": code, "message": msg, **(extra or {})}}, status_code=status)

@app.exception_handler(ApiError)
async def _api(_, e): return err(e.status, e.code, e.msg, e.extra)
@app.exception_handler(RequestValidationError)
async def _val(_, e): return err(422, "INVALID_INPUT", "Request failed validation")
@app.exception_handler(Exception)
async def _any(_, e): return err(500, "INTERNAL_ERROR", "Something went wrong")

@app.middleware("http")
async def guard(request: Request, call_next):
    if int(request.headers.get("content-length") or 0) > config.MAX_BODY_BYTES:
        return err(413, "PAYLOAD_TOO_LARGE", "Request body too large")
    try:
        resp = await call_next(request)
    except Exception:
        resp = err(500, "INTERNAL_ERROR", "Something went wrong")
    resp.headers.update({"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
                         "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"})
    return resp

# ---------- helpers ----------
def client_ip(r: Request) -> str:
    if config.TRUST_PROXY and r.headers.get("x-forwarded-for"):
        return r.headers["x-forwarded-for"].split(",")[0].strip()
    return r.client.host if r.client else "unknown"

def ua_of(r: Request) -> str: return r.headers.get("user-agent", "")[:300]

def auth(r: Request, roles: Optional[List[str]] = None) -> dict:
    tok = r.cookies.get("sid")
    s = db.q("SELECT s.*, u.username, u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=?",
             (hashlib.sha256((tok or "").encode()).hexdigest(),), one=True)
    now = time.time()
    if not s or s["revoked_at"] or s["expires"] < now:
        db.audit("anonymous", "none", "UNAUTHENTICATED_REQUEST", "DENIED", {"path": r.url.path})
        raise ApiError(401, "AUTH_REQUIRED", "Authentication required")
    settings = db.get_settings()
    risk = eng.score_session_risk(s, ua_of(r), client_ip(r), settings["risk_threshold"])
    if risk["action"] == "REVOKE":
        db.x("UPDATE sessions SET revoked_at=?, revoke_reason=? WHERE id=?", (now, "RISK_THRESHOLD", s["id"]))
        db.audit(s["username"], s["role"], "SESSION_AUTO_REVOKED", "DENIED", {"session": s["id"], "risk": risk})
        raise ApiError(401, "SESSION_REVOKED", "Session is no longer valid")
    if risk["action"] == "FLAG":
        db.audit(s["username"], s["role"], "SESSION_RISK_FLAG", "WARN", {"session": s["id"], "risk": risk})
    if r.method not in ("GET", "HEAD") and not secrets.compare_digest(r.headers.get("x-csrf-token", ""), s["csrf"]):
        db.audit(s["username"], s["role"], "CSRF_REJECTED", "DENIED", {"path": r.url.path})
        raise ApiError(403, "CSRF_INVALID", "Access denied")
    if roles and s["role"] not in roles:
        db.audit(s["username"], s["role"], "AUTHZ_DENIED", "DENIED", {"path": r.url.path})
        raise ApiError(403, "FORBIDDEN", "Access denied")
    db.x("UPDATE sessions SET last_seen=? WHERE id=?", (now, s["id"]))
    return s

# ---------- models ----------
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=128)

class Op(BaseModel):
    op_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
    note_id: Optional[str] = Field(default=None, max_length=64)
    base_version: int = Field(ge=0, le=1_000_000)
    iv: str = Field(max_length=200)
    ct: str = Field(min_length=1)
    tag: Optional[str] = Field(default=None, max_length=40)

class SyncIn(BaseModel): ops: List[Op] = Field(max_length=50)

class SettingsIn(BaseModel):
    session_ttl_minutes: Optional[int] = Field(default=None, ge=1, le=1440)
    max_failed_logins: Optional[int] = Field(default=None, ge=1, le=20)
    lockout_window_seconds: Optional[int] = Field(default=None, ge=10, le=3600)
    risk_threshold: Optional[int] = Field(default=None, ge=10, le=100)
    max_note_bytes: Optional[int] = Field(default=None, ge=100, le=100000)

class RiskIn(BaseModel):
    session_id: str = Field(max_length=64)
    user_agent: str = Field(max_length=300)
    ip: str = Field(max_length=64)

class CacheIn(BaseModel):
    path: str = Field(max_length=200)
    sha256: str = Field(max_length=64)

class DeviceIn(BaseModel): username: Optional[str] = Field(default=None, max_length=40)
class ExplainIn(BaseModel): event_id: int = Field(ge=1)

# ---------- auth ----------
@app.get("/api/health")
def health(): return {"status": "ok", "engine_version": eng.ENGINE_VERSION}

@app.post("/api/auth/login")
def login(body: LoginIn, r: Request):
    st, ip = db.get_settings(), client_ip(r)
    key = (ip, body.username.lower())
    if limiter.blocked(key, st["max_failed_logins"], st["lockout_window_seconds"]):
        db.audit("anonymous", "none", "LOGIN_RATE_LIMITED", "DENIED", {"ip": ip})
        raise ApiError(429, "RATE_LIMITED", "Too many attempts. Try again later.")
    u = db.q("SELECT * FROM users WHERE username=?", (body.username,), one=True)
    ok = bcrypt.checkpw(body.password.encode(), u["pw_hash"] if u else DUMMY_HASH) and u is not None
    if not ok:
        limiter.record_fail(key)
        db.audit(u["username"] if u else "unknown", u["role"] if u else "none", "LOGIN", "FAILED", {"ip": ip})
        raise ApiError(401, "INVALID_CREDENTIALS", "Invalid username or password")
    limiter.reset(key)
    tok, csrf, sid, now = secrets.token_urlsafe(32), secrets.token_urlsafe(24), str(uuid.uuid4()), time.time()
    ua = ua_of(r)
    db.x("INSERT INTO sessions(id,token_hash,csrf,user_id,ua_hash,ua,ip,created,last_seen,expires) VALUES(?,?,?,?,?,?,?,?,?,?)",
         (sid, hashlib.sha256(tok.encode()).hexdigest(), csrf, u["id"], eng.sha256_hex(ua.encode()), ua, ip,
          now, now, now + st["session_ttl_minutes"] * 60))
    db.audit(u["username"], u["role"], "LOGIN", "OK", {"session": sid, "ip": ip})
    resp = JSONResponse({"user": {"username": u["username"], "role": u["role"]}, "csrf": csrf, "session_id": sid})
    resp.set_cookie("sid", tok, httponly=True, samesite="strict", secure=config.COOKIE_SECURE,
                    max_age=st["session_ttl_minutes"] * 60, path="/")
    return resp

@app.get("/api/auth/me")
def me(r: Request):
    s = auth(r)
    return {"user": {"username": s["username"], "role": s["role"]}, "csrf": s["csrf"], "session_id": s["id"]}

@app.post("/api/auth/logout")
def logout(r: Request):
    s = auth(r)
    db.x("UPDATE sessions SET revoked_at=?, revoke_reason='LOGOUT' WHERE id=?", (time.time(), s["id"]))
    db.audit(s["username"], s["role"], "LOGOUT", "OK", {"session": s["id"]})
    resp = JSONResponse({"ok": True}); resp.delete_cookie("sid", path="/"); return resp

# ---------- sessions / revocation (FR-6) ----------
@app.get("/api/sessions")
def sessions(r: Request):
    s = auth(r)
    sql = "SELECT s.id,u.username,s.ip,s.ua,s.created,s.last_seen,s.expires,s.revoked_at,s.revoke_reason FROM sessions s JOIN users u ON u.id=s.user_id"
    rows = db.q(sql + " ORDER BY s.created DESC LIMIT 100") if s["role"] == "admin" else \
           db.q(sql + " WHERE s.user_id=? ORDER BY s.created DESC LIMIT 100", (s["user_id"],))
    return {"sessions": rows, "current": s["id"]}

@app.post("/api/sessions/{sid}/revoke")
def revoke(sid: str, r: Request):
    s = auth(r)
    t = db.q("SELECT * FROM sessions WHERE id=?", (sid,), one=True)
    if not t or (s["role"] != "admin" and t["user_id"] != s["user_id"]):
        db.audit(s["username"], s["role"], "REVOKE_SESSION", "DENIED", {"target": sid})
        raise ApiError(403, "FORBIDDEN", "Access denied")
    db.x("UPDATE sessions SET revoked_at=?, revoke_reason=? WHERE id=? AND revoked_at IS NULL", (time.time(), "REMOTE_REVOKE", sid))
    db.audit(s["username"], s["role"], "REVOKE_SESSION", "OK", {"target": sid})
    return {"revoked": sid}

@app.post("/api/device-loss")
def device_loss(body: DeviceIn, r: Request):
    s = auth(r)
    target = body.username or s["username"]
    if s["role"] != "admin" and target != s["username"]:
        db.audit(s["username"], s["role"], "DEVICE_LOSS", "DENIED", {"target": target})
        raise ApiError(403, "FORBIDDEN", "Access denied")
    u = db.q("SELECT id FROM users WHERE username=?", (target,), one=True)
    if not u: raise ApiError(404, "NOT_FOUND", "User not found")
    n = len(db.q("SELECT id FROM sessions WHERE user_id=? AND revoked_at IS NULL", (u["id"],)))
    db.x("UPDATE sessions SET revoked_at=?, revoke_reason='DEVICE_LOSS' WHERE user_id=? AND revoked_at IS NULL", (time.time(), u["id"]))
    db.audit(s["username"], s["role"], "DEVICE_LOSS", "OK", {"target": target, "sessions_revoked": n})
    return {"target": target, "sessions_revoked": n}

# ---------- encrypted notes + offline queue sync (FR-3, FR-4) ----------
@app.get("/api/notes")
def notes(r: Request):
    s = auth(r, ["admin", "analyst"])
    return {"notes": db.q("SELECT id,tag,iv,ct,version,updated FROM notes WHERE user_id=? ORDER BY updated DESC", (s["user_id"],))}

@app.post("/api/notes/sync")
def sync(body: SyncIn, r: Request):
    s = auth(r, ["admin", "analyst"])
    st, results = db.get_settings(), []
    for op in body.ops:
        prior = db.q("SELECT result FROM ops WHERE op_id=? AND user_id=?", (op.op_id, s["user_id"]), one=True)
        if prior:
            results.append({**json.loads(prior["result"]), "status": "duplicate"}); continue
        res = {"op_id": op.op_id, "note_id": op.note_id}
        scan = eng.scan_text(op.tag or "")
        if not scan["safe"]:
            res.update(status="rejected", code="XSS_DETECTED", indicators=scan["indicators"])
        elif len(op.ct) > st["max_note_bytes"]:
            res.update(status="rejected", code="PAYLOAD_TOO_LARGE")
        elif op.note_id is None:
            nid = str(uuid.uuid4())
            db.x("INSERT INTO notes VALUES(?,?,?,?,?,?,?)", (nid, s["user_id"], op.tag, op.iv, op.ct, 1, time.time()))
            res.update(status="applied", note_id=nid, version=1, reason="new note")
        else:
            n = db.q("SELECT version FROM notes WHERE id=? AND user_id=?", (op.note_id, s["user_id"]), one=True)
            if not n:
                res.update(status="rejected", code="NOT_FOUND")
            else:
                d = eng.resolve_note_op(n["version"], op.base_version)
                if d["status"] == "applied":
                    db.x("UPDATE notes SET tag=?,iv=?,ct=?,version=?,updated=? WHERE id=?",
                         (op.tag, op.iv, op.ct, d["new_version"], time.time(), op.note_id))
                res.update(status=d["status"], version=d["new_version"], reason=d["reason"])
        db.x("INSERT INTO ops VALUES(?,?,?)", (op.op_id, s["user_id"], json.dumps(res)))
        db.audit(s["username"], s["role"], "NOTE_SYNC", res["status"].upper(),
                 {"op": op.op_id, "note": res.get("note_id"), "code": res.get("code"), "indicators": res.get("indicators"), "reason": res.get("reason")})
        results.append(res)
    return {"results": results}

# ---------- cache/update policy (FR-5) ----------
@app.get("/api/cache-policy")
def cache_policy(): return eng.build_manifest(config.FRONTEND_DIR)

@app.post("/api/cache-policy/verify")
def cache_verify(body: CacheIn, r: Request):
    s = auth(r, ["admin", "analyst"])
    d = eng.verify_cache_entry(body.path, body.sha256, eng.build_manifest(config.FRONTEND_DIR))
    db.audit(s["username"], s["role"], "CACHE_VERIFY", d["decision"], {"path": body.path, "rule": d["rule"]})
    return d

# ---------- risk simulation (T2) ----------
@app.post("/api/risk/simulate")
def risk_sim(body: RiskIn, r: Request):
    s = auth(r, ["admin", "analyst"])
    t = db.q("SELECT * FROM sessions WHERE id=?", (body.session_id,), one=True)
    if not t or (s["role"] != "admin" and t["user_id"] != s["user_id"]): raise ApiError(404, "NOT_FOUND", "Session not found")
    d = eng.score_session_risk(t, body.user_agent, body.ip, db.get_settings()["risk_threshold"])
    db.audit(s["username"], s["role"], "RISK_SIMULATED", d["action"], {"session": t["id"], "risk": d})
    return d

# ---------- admin: settings + audit (FR-7) ----------
@app.get("/api/admin/settings")
def get_settings(r: Request):
    auth(r, ["admin"]); return db.get_settings()

@app.put("/api/admin/settings")
def put_settings(body: SettingsIn, r: Request):
    s = auth(r, ["admin"])
    old, ch = db.get_settings(), {k: v for k, v in body.model_dump().items() if v is not None}
    for k, v in ch.items(): db.x("UPDATE settings SET value=? WHERE key=?", (v, k))
    db.audit(s["username"], s["role"], "CONFIG_CHANGE", "OK", {"before": {k: old[k] for k in ch}, "after": ch})
    return db.get_settings()

@app.get("/api/audit")
def audit_list(r: Request, limit: int = 100, action: Optional[str] = None):
    auth(r, ["admin"])
    limit = max(1, min(limit, 500))
    if action: return {"events": db.q("SELECT * FROM audit WHERE action=? ORDER BY id DESC LIMIT ?", (action[:40], limit))}
    return {"events": db.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))}

@app.get("/api/audit/verify")
def audit_verify(r: Request):
    auth(r, ["admin"]); return db.verify_audit_chain()

@app.get("/api/audit/export")
def audit_export(r: Request):
    s = auth(r, ["admin"])
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["id", "ts", "actor", "role", "action", "outcome", "detail", "hash"])
    for e in db.q("SELECT * FROM audit ORDER BY id"):
        w.writerow([str(e[k]).lstrip("=+-@") if k in ("actor", "detail") else e[k] for k in ("id", "ts", "actor", "role", "action", "outcome", "detail", "hash")])
    db.audit(s["username"], s["role"], "AUDIT_EXPORT", "OK")
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit.csv"})

@app.post("/api/explain")
def explain(body: ExplainIn, r: Request):
    s = auth(r, ["admin"])
    ev = db.q("SELECT id,actor,role,action,outcome,detail FROM audit WHERE id=?", (body.event_id,), one=True)
    if not ev: raise ApiError(404, "NOT_FOUND", "Event not found")
    out = explain_event(ev)
    db.audit(s["username"], s["role"], "EXPLAIN", "OK", {"event": body.event_id, "source": out["source"]})
    return out

@app.get("/api/report")
def report(r: Request):
    s = auth(r)
    counts = db.q("SELECT action,outcome,COUNT(*) AS n FROM audit GROUP BY action,outcome ORDER BY n DESC")
    db.audit(s["username"], s["role"], "REPORT_VIEW", "OK")
    return {"generated": time.time(), "engine_version": eng.ENGINE_VERSION, "settings": db.get_settings(),
            "event_counts": counts, "audit_chain": db.verify_audit_chain()}
