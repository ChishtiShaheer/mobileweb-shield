"""Tiny frontend server: serves ./frontend and reverse-proxies /api to the backend (same-origin => cookies just work)."""
import mimetypes, os, sys, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    from dotenv import load_dotenv; load_dotenv(ROOT / ".env")
except ImportError:
    pass
WEB = Path(os.environ.get("FRONTEND_DIR", ROOT / "frontend")).resolve()
BACKEND = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
HOST, PORT = os.environ.get("FRONTEND_HOST", "127.0.0.1"), int(os.environ.get("FRONTEND_PORT", "5173"))
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
HOP = {"connection", "transfer-encoding", "content-length", "keep-alive", "host"}

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, headers):
        self.send_response(code)
        for k, v in headers: self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def _proxy(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n) if n else None
        req = urllib.request.Request(BACKEND + self.path, data=data, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in HOP: req.add_header(k, v)
        req.add_header("X-Forwarded-For", self.client_address[0])
        try:
            r = urllib.request.urlopen(req, timeout=15); code = r.status
        except urllib.error.HTTPError as e:
            r, code = e, e.code
        except Exception:
            return self._send(502, b'{"error":{"code":"BACKEND_UNAVAILABLE","message":"Backend is not running"}}',
                              [("Content-Type", "application/json")])
        hdrs = [(k, v) for k, v in r.headers.items() if k.lower() not in HOP and k.lower() != "set-cookie"]
        hdrs += [("Set-Cookie", c) for c in r.headers.get_all("Set-Cookie") or []]
        self._send(code, r.read(), hdrs)

    def _static(self):
        rel = self.path.split("?")[0]
        f = (WEB / ("index.html" if rel == "/" else rel.lstrip("/"))).resolve()
        if WEB not in f.parents and f != WEB or not f.is_file():
            return self._send(404, b"Not found", [("Content-Type", "text/plain")])
        ctype = "application/manifest+json" if f.suffix == ".webmanifest" else (mimetypes.guess_type(f.name)[0] or "application/octet-stream")
        self._send(200, f.read_bytes(), [("Content-Type", ctype), ("Content-Security-Policy", CSP),
                   ("X-Content-Type-Options", "nosniff"), ("Cache-Control", "no-cache"), ("Referrer-Policy", "no-referrer")])

    def _route(self):
        self._proxy() if self.path.startswith("/api") else self._static()
    do_GET = do_POST = do_PUT = do_DELETE = _route
    def log_message(self, *a): pass

if __name__ == "__main__":
    print(f"Frontend on http://{HOST}:{PORT}  ->  proxying /api to {BACKEND}", flush=True)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
