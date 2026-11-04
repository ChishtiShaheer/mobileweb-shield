"""python scripts/run.py backend|frontend|test  (uses .venv automatically)"""
import os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = ROOT / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
if not PY.exists():
    sys.exit("No .venv found. Run:  python scripts/setup.py")
what = sys.argv[1] if len(sys.argv) > 1 else ""
host = os.environ.get("HOST", "127.0.0.1")
cmds = {
    "backend": [str(PY), "-m", "uvicorn", "app.main:app", "--app-dir", str(ROOT / "backend"), "--host", host, "--port", "8000"],
    "frontend": [str(PY), str(ROOT / "scripts" / "frontend_server.py")],
    "test": [str(PY), "-m", "pytest", "-v", str(ROOT / "tests")],
}
if what not in cmds:
    sys.exit("usage: python scripts/run.py backend|frontend|test")
os.chdir(ROOT)
sys.exit(subprocess.call(cmds[what]))
