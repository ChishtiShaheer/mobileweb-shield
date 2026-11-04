import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["DB_PATH"] = str(Path(tempfile.mkdtemp()) / "test.db")
os.environ["GEMINI_API_KEY"] = ""
os.environ["FRONTEND_DIR"] = str(ROOT / "frontend")
import pytest
from fastapi.testclient import TestClient
from app.main import app, limiter
from app import db

PW = {"admin": "Admin#Shield2026", "analyst": "Analyst#Shield2026", "viewer": "Viewer#Shield2026"}
UA = "TestBrowser/1.0"

@pytest.fixture(autouse=True)
def fresh():
    db.reset_db(); limiter.reset(); yield

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

class Sess:
    def __init__(self, c, role, ua=UA):
        self.c, self.h = c, {"user-agent": ua}
        r = c.post("/api/auth/login", json={"username": role, "password": PW[role]}, headers=self.h)
        assert r.status_code == 200, r.text
        self.csrf, self.sid = r.json()["csrf"], r.json()["session_id"]
        self.h["x-csrf-token"] = self.csrf
    def get(self, p, **k): return self.c.get(p, headers=self.h, **k)
    def post(self, p, j=None): return self.c.post(p, json=j, headers=self.h)
    def put(self, p, j=None): return self.c.put(p, json=j, headers=self.h)

@pytest.fixture
def login():
    # each login gets its own client => its own cookie jar (= its own device)
    return lambda role, ua=UA: Sess(TestClient(app), role, ua)
