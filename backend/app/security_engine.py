"""Security engine: pure, independently testable functions (no web/db imports)."""
import hashlib, re, time
from collections import defaultdict
from pathlib import Path

ENGINE_VERSION = "1.0.0"

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ---------- password policy ----------
def check_password_policy(pw: str) -> list:
    r = []
    if len(pw) < 10: r.append("MIN_LENGTH_10")
    if not re.search(r"[a-z]", pw): r.append("NEEDS_LOWERCASE")
    if not re.search(r"[A-Z]", pw): r.append("NEEDS_UPPERCASE")
    if not re.search(r"\d", pw): r.append("NEEDS_DIGIT")
    return r

# ---------- XSS / injection scanning (T4) ----------
XSS_RULES = {
    "script_tag": r"<\s*/?\s*script",
    "event_handler": r"\bon[a-z]+\s*=",
    "javascript_uri": r"javascript\s*:",
    "dangerous_tag": r"<\s*(iframe|img|svg|object|embed|link|meta|style)\b",
    "html_entity_bypass": r"&#x?[0-9a-f]+;?[a-z]*script",
}
def scan_text(text: str) -> dict:
    hits = [n for n, rx in XSS_RULES.items() if re.search(rx, text or "", re.I)]
    return {"safe": not hits, "indicators": hits, "rules_version": ENGINE_VERSION}

# ---------- session risk (T2 stolen session) ----------
def score_session_risk(session: dict, ua: str, ip: str, threshold: int) -> dict:
    reasons, score = [], 0
    if session["ua_hash"] != sha256_hex((ua or "").encode()):
        reasons.append({"rule": "USER_AGENT_CHANGED", "points": 60}); score += 60
    if session["ip"] != ip:
        reasons.append({"rule": "IP_CHANGED", "points": 20}); score += 20
    action = "REVOKE" if score >= threshold else ("FLAG" if score else "ALLOW")
    return {"score": score, "threshold": threshold, "action": action,
            "reasons": reasons, "engine_version": ENGINE_VERSION}

# ---------- offline/online conflict policy (T1) ----------
def resolve_note_op(server_version: int, base_version: int) -> dict:
    """Optimistic concurrency: a write is applied only if it was based on the latest version."""
    if base_version == server_version:
        return {"status": "applied", "new_version": server_version + 1,
                "reason": "base_version matches server_version"}
    return {"status": "conflict", "new_version": server_version,
            "reason": f"base_version {base_version} != server_version {server_version}; server copy kept"}

# ---------- cache / update policy (T3 cache poisoning) ----------
def build_manifest(frontend_dir: Path) -> dict:
    assets = {}
    for f in sorted(frontend_dir.glob("*")):
        if f.is_file() and f.name != "sw.js":
            assets["/" + f.name] = sha256_hex(f.read_bytes())
    if "/index.html" in assets: assets["/"] = assets["/index.html"]
    version = sha256_hex("".join(f"{k}{v}" for k, v in assets.items()).encode())[:12]
    return {"version": version, "assets": assets, "policy": "same-origin GET, allowlisted, SHA-256 verified; /api never cached"}

def verify_cache_entry(path: str, sha256: str, manifest: dict) -> dict:
    if path.startswith("/api"):
        return {"decision": "DENY", "rule": "API_NEVER_CACHED"}
    if path not in manifest["assets"]:
        return {"decision": "DENY", "rule": "PATH_NOT_ALLOWLISTED"}
    if manifest["assets"][path] != (sha256 or "").lower():
        return {"decision": "DENY", "rule": "HASH_MISMATCH"}
    return {"decision": "ALLOW", "rule": "HASH_MATCHES_MANIFEST"}

# ---------- login rate limiting ----------
class LoginLimiter:
    def __init__(self): self.fail = defaultdict(list)
    def blocked(self, key, max_fail, window) -> bool:
        now = time.time()
        self.fail[key] = [t for t in self.fail[key] if now - t < window]
        return len(self.fail[key]) >= max_fail
    def record_fail(self, key): self.fail[key].append(time.time())
    def reset(self, key=None):
        self.fail.pop(key, None) if key else self.fail.clear()
