"""Mandatory evaluation cases T1-T6 and T-final (see EVALUATION.md)."""
import json, re, hashlib
from pathlib import Path
from fastapi.testclient import TestClient
from conftest import Sess
from app.main import app
from app import db, config

ROOT = Path(__file__).resolve().parents[1]
S = json.loads((ROOT / "tests/fixtures/samples.json").read_text())
def op(i="op-00000001", nid=None, base=0, tag="t", ct="Y2lwaGVy"): return {"op_id": i, "note_id": nid, "base_version": base, "iv": "aXY=.c2FsdA==", "ct": ct, "tag": tag}

# ---------- FR-1 / FR-2 ----------
def test_fr1_pwa_installable_files():
    man = json.loads((ROOT / "frontend/manifest.webmanifest").read_text())
    sizes = {i["sizes"] for i in man["icons"]}
    assert {"192x192", "512x512"} <= sizes and man["display"] == "standalone" and (ROOT / "frontend/sw.js").exists()

def test_fr2_login_good_bad_and_logout(client, login):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).json()["error"]["code"] == "INVALID_CREDENTIALS"
    a = login("admin"); assert a.get("/api/auth/me").status_code == 200
    a.post("/api/auth/logout"); assert a.get("/api/auth/me").status_code == 401

def test_login_rate_limit(client):
    for _ in range(5): client.post("/api/auth/login", json={"username": "admin", "password": "x"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin#Shield2026"})
    assert r.status_code == 429 and r.json()["error"]["code"] == "RATE_LIMITED"

# ---------- T1 offline/online conflicts ----------
def test_T1_conflict_duplicate_and_ciphertext_only(login):
    a = login("analyst")
    r1 = a.post("/api/notes/sync", {"ops": [op("op-00000001")]}).json()["results"][0]
    nid = r1["note_id"]; assert r1["status"] == "applied" and r1["version"] == 1
    assert a.post("/api/notes/sync", {"ops": [op("op-00000002", nid, 1)]}).json()["results"][0]["version"] == 2   # online edit
    stale = a.post("/api/notes/sync", {"ops": [op("op-00000003", nid, 1)]}).json()["results"][0]                    # offline edit from v1
    assert stale["status"] == "conflict" and stale["version"] == 2
    dup = a.post("/api/notes/sync", {"ops": [op("op-00000002", nid, 1)]}).json()["results"][0]                      # replayed queue
    assert dup["status"] == "duplicate"
    assert db.q("SELECT ct FROM notes WHERE id=?", (nid,), one=True)["ct"] == "Y2lwaGVy"   # opaque ciphertext stored as received

# ---------- T2 stolen session ----------
def test_T2_stolen_session(login):
    a = login("analyst")
    sim = a.post("/api/risk/simulate", {"session_id": a.sid, "user_agent": "Evil/1", "ip": "203.0.113.9"}).json()
    assert sim["action"] == "REVOKE" and {r["rule"] for r in sim["reasons"]} == {"USER_AGENT_CHANGED", "IP_CHANGED"}
    stolen = a.c.get("/api/notes", headers={"user-agent": "Evil/1"})   # same cookie, different device
    assert stolen.status_code == 401 and stolen.json()["error"]["code"] == "SESSION_REVOKED"
    assert a.c.get("/api/notes", headers={"user-agent": "TestBrowser/1.0"}).status_code == 401  # real owner is revoked too (fail closed)
    assert db.q("SELECT 1 FROM audit WHERE action='SESSION_AUTO_REVOKED'")

# ---------- T3 cache poisoning ----------
def test_T3_cache_poisoning(login):
    a = login("analyst"); man = a.get("/api/cache-policy").json()
    for c in S["cache_cases"]:
        h = "0" * 64 if c["tamper"] else man["assets"].get(c["path"], "x")
        assert a.post("/api/cache-policy/verify", {"path": c["path"], "sha256": h}).json()["decision"] == c["expect"], c
    real = hashlib.sha256((ROOT / "frontend/app.js").read_bytes()).hexdigest()
    assert man["assets"]["/app.js"] == real and "/sw.js" not in man["assets"]

# ---------- T4 XSS ----------
def test_T4_xss_rejected_and_headers(client, login):
    a = login("analyst")
    for i, t in enumerate(S["malicious_tags"]):
        r = a.post("/api/notes/sync", {"ops": [op(f"xss-{i:06d}", tag=t)]}).json()["results"][0]
        assert r["status"] == "rejected" and r["code"] == "XSS_DETECTED" and r["indicators"], t
    ok = a.post("/api/notes/sync", {"ops": [op("good-00001", tag=S["benign_tags"][0])]}).json()["results"][0]
    assert ok["status"] == "applied"
    js = (ROOT / "frontend/app.js").read_text(); assert "innerHTML" not in js and "eval(" not in js   # no HTML sinks in UI code
    assert "script-src 'self'" in (ROOT / "scripts/frontend_server.py").read_text()

# ---------- T5 device loss ----------
def test_T5_device_loss(client, login):
    a1, a2, v = login("analyst"), login("analyst", ua="Phone/2"), login("viewer")
    assert a1.post("/api/device-loss", {"username": "viewer"}).status_code == 403          # cannot revoke others
    r = a1.post("/api/device-loss", {}).json(); assert r["sessions_revoked"] == 2
    assert a2.get("/api/notes").status_code == 401 and a1.get("/api/notes").status_code == 401
    assert v.get("/api/report").status_code == 200                                           # others unaffected
    adm = login("admin"); assert adm.post("/api/device-loss", {"username": "viewer"}).json()["sessions_revoked"] == 1

def test_remote_revocation_by_admin(login):
    a, adm = login("analyst"), login("admin")
    assert adm.post(f"/api/sessions/{a.sid}/revoke").status_code == 200 and a.get("/api/notes").status_code == 401

# ---------- T6 responsive accessibility (static checks; manual checklist in EVALUATION.md) ----------
def test_T6_accessibility_static():
    html = (ROOT / "frontend/index.html").read_text()
    assert 'lang="en"' in html and 'name="viewport"' in html and 'class="skip"' in html and 'aria-live' in html
    ids = set(re.findall(r'<input id="(\w+)"', html)) | set(re.findall(r'<textarea id="(\w+)"', html))
    labelled = set(re.findall(r'<label for="(\w+)"', html))
    assert ids <= labelled, ids - labelled
    css = (ROOT / "frontend/style.css").read_text()
    assert "prefers-reduced-motion" in css and "focus-visible" in css and "min-height:44px" in css

# ---------- Authorization / FR-7 ----------
def test_authorization_and_generic_denial(client, login):
    v = login("viewer")
    for m, p in (("get", "/api/audit"), ("get", "/api/notes"), ("get", "/api/admin/settings")):
        r = getattr(v, m)(p); assert r.status_code == 403 and r.json()["error"]["message"] == "Access denied"
    assert db.q("SELECT 1 FROM audit WHERE action='AUTHZ_DENIED' AND actor='viewer'")
    assert client.get("/api/audit").status_code == 401

def test_csrf_enforced(client, login):
    a = login("analyst"); a.h.pop("x-csrf-token")
    assert a.post("/api/device-loss", {}).json()["error"]["code"] == "CSRF_INVALID"

def test_admin_config_change_traceable(login):
    adm = login("admin")
    adm.put("/api/admin/settings", {"risk_threshold": 90})
    ev = db.q("SELECT detail FROM audit WHERE action='CONFIG_CHANGE'", one=True)["detail"]
    assert '"risk_threshold": 90' in ev
    a = login("analyst")
    assert a.post("/api/risk/simulate", {"session_id": a.sid, "user_agent": "Other/1", "ip": "127.0.0.1"}).json()["action"] == "FLAG"  # 60 < 90 now
    assert adm.get("/api/audit/verify").json()["valid"] and "id,ts,actor" in adm.get("/api/audit/export").text

def test_audit_append_only_and_tamper_evident(login):
    import sqlite3, pytest
    login("admin")
    with pytest.raises(sqlite3.DatabaseError): db.x("DELETE FROM audit")
    with pytest.raises(sqlite3.DatabaseError): db.x("UPDATE audit SET actor='x'")
    assert db.verify_audit_chain()["valid"]

def test_explain_fallback_without_key(login):
    adm = login("admin"); r = adm.post("/api/explain", {"event_id": 1}).json()
    assert r["source"] == "rule-based" and r["text"]

# ---------- T-final ----------
def test_Tfinal_malformed_oversized_unauth_repeat_restart(client, login):
    a = login("analyst")
    assert a.post("/api/notes/sync", {"ops": "nope"}).json()["error"]["code"] == "INVALID_INPUT"
    assert a.post("/api/notes/sync", {"ops": [op(ct="A" * 30000)]}).json()["results"][0]["code"] == "PAYLOAD_TOO_LARGE"
    assert client.post("/api/notes/sync", json={"ops": []}, headers={"content-length": "999999"}).status_code == 413
    assert a.c.post("/api/auth/login", content=b"{bad json", headers={"content-type": "application/json"}).json()["error"]["code"] == "INVALID_INPUT"
    for _ in range(3): last = a.post("/api/notes/sync", {"ops": [op("same-op-001")]}).json()["results"][0]
    assert last["status"] == "duplicate" and len(db.q("SELECT id FROM notes")) == 1
    body = json.dumps(a.get("/api/nope").json()); assert "Traceback" not in body
    db.init_db()                                                                              # simulated restart
    with TestClient(app) as c2:
        c2.cookies.set("sid", a.c.cookies.get("sid"))
        assert c2.get("/api/notes", headers={"user-agent": "TestBrowser/1.0"}).json()["notes"]
