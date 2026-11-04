"""One-command setup: creates .venv, installs requirements.txt, creates .env. Works on Windows/macOS/Linux."""
import shutil, subprocess, sys, venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
PY = VENV / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

if not PY.exists():
    print("Creating virtual environment in .venv ...")
    venv.create(VENV, with_pip=True)
print("Installing dependencies (pip install -r requirements.txt) ...")
subprocess.check_call([str(PY), "-m", "pip", "install", "--upgrade", "pip", "-q"])
subprocess.check_call([str(PY), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")])
if not (ROOT / ".env").exists():
    shutil.copy(ROOT / ".env.example", ROOT / ".env")
    print("Created .env  (add GEMINI_API_KEY there for AI explanations)")
print("\nSetup complete. Next: run 'Run Backend' and 'Run Frontend' (VS Code buttons) or:")
print("  python scripts/run.py backend    |    python scripts/run.py frontend    |    python scripts/run.py test")
