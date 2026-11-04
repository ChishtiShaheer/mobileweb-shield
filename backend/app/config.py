import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

def _p(v: str) -> Path:
    p = Path(v)
    return p if p.is_absolute() else ROOT / p

DB_PATH = _p(os.environ.get("DB_PATH", "data/mobileweb.db"))
FRONTEND_DIR = _p(os.environ.get("FRONTEND_DIR", "frontend"))
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
MAX_BODY_BYTES = 128 * 1024
SEED = {
    "admin": ("admin", os.environ.get("ADMIN_PASSWORD", "Admin#Shield2026")),
    "analyst": ("analyst", os.environ.get("ANALYST_PASSWORD", "Analyst#Shield2026")),
    "viewer": ("viewer", os.environ.get("VIEWER_PASSWORD", "Viewer#Shield2026")),
}
DEFAULT_SETTINGS = {
    "session_ttl_minutes": 60,   # absolute session lifetime
    "max_failed_logins": 5,      # per (ip, username) inside the window
    "lockout_window_seconds": 300,
    "risk_threshold": 50,        # session risk score >= threshold => revoke
    "max_note_bytes": 20000,     # max ciphertext size per note
}
