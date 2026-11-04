# MobileWeb Shield: Progressive Web App Security Suite
Class 2, Group 17 | Proposal 32 | Mobile and Web Security

A mobile-first installable PWA with a Python (FastAPI) API and a SQLite store. It demonstrates **secure login, end-to-end encrypted notes, an offline queue with conflict handling, an integrity-checked cache/update policy, remote session revocation, device-loss response, and a tamper-evident audit view**. Every security decision is returned with rule names, scores, reasons and the engine version, so it can be reproduced.

## 1. Quick start (3 steps)
Requires **Python 3.10+** (and optionally Docker).
```bash
python scripts/setup.py          # creates .venv, runs pip install -r requirements.txt, creates .env
python scripts/run.py backend    # terminal 1  -> API on http://127.0.0.1:8000
python scripts/run.py frontend   # terminal 2  -> App on http://127.0.0.1:5173
```
Open **http://127.0.0.1:5173**. (Windows: use `python`; macOS/Linux: `python3` if needed.)

### VS Code "buttons"
Open the folder in VS Code and accept the recommended extension *Action Buttons*. The status bar then shows **Setup | Backend | Frontend | Tests | Docker** buttons. Without the extension: `Terminal > Run Task...` offers the same tasks (including *Run Backend + Frontend*).

### Docker (optional)
```bash
docker compose up --build        # open http://localhost:5173
```
Only the frontend port is published; the backend is reachable only through the frontend proxy.

### Run tests
```bash
python scripts/run.py test       # 19 automated tests, ~25 s (bcrypt hashing dominates)
```

## 2. Demo accounts (seeded; change in `.env` before any real use)
| Role | Username | Password | Can do |
|---|---|---|---|
| Administrator | `admin` | `Admin#Shield2026` | settings, audit view/verify/export, AI explain, revoke any session, notes, tools |
| Analyst/operator | `analyst` | `Analyst#Shield2026` | encrypted notes + queue, risk simulation, cache verification, own sessions |
| Restricted viewer | `viewer` | `Viewer#Shield2026` | login, own sessions, read-only report (notes/audit denied) |

## 3. Gemini 2.5 Flash (optional)
Put your key in `.env` as `GEMINI_API_KEY=...` (get one at aistudio.google.com). In **Administration > Load audit log > Explain** the model explains a (secret-redacted) audit event. Without a key the app falls back to a rule-based explanation, so everything still works.

## 4. Architecture
```
Browser (PWA: UI, Web Crypto AES-GCM, offline queue, service worker)
   |  same-origin /api  (scripts/frontend_server.py proxies; cookie + CSRF header)
API layer       backend/app/main.py          authn, authz, validation, safe errors, rate limit
Security engine backend/app/security_engine.py  pure functions: XSS scan, session risk, conflict policy, cache policy
Repository      backend/app/db.py            parameterized SQLite, append-only hash-chained audit
AI helper       backend/app/explain.py       Gemini 2.5 Flash explanations (redacted input)
Fixtures        tests/fixtures/samples.json  safe sample inputs
```
Requirement mapping: FR-1 `manifest.webmanifest`+`sw.js` | FR-2 `/api/auth/*` (bcrypt, HttpOnly SameSite=Strict cookie, CSRF, lockout) | FR-3 `app.js` Web Crypto + `/api/notes` (server sees ciphertext only) | FR-4 offline queue in `app.js` + `/api/notes/sync` | FR-5 `/api/cache-policy` + SHA-256-verified `sw.js` | FR-6 `/api/sessions/*`, `/api/device-loss`, automatic risk-based revocation | FR-7 `/api/audit*`.
Storage note: no IndexedDB is used. The encrypted notes and queue live in `localStorage` as **ciphertext**; the passphrase is held only in memory.

## 5. Demo script (10-15 min)
1. Log in as `analyst`. Enter a passphrase, tag and note, then **Save**. The note is encrypted, queued, synced, and shows `v1 synced`. Decrypt it with the passphrase.
2. **Offline/conflict (T1):** DevTools > Network > *Offline*. Edit/save two notes: the queue grows. Go online: it flushes. Create a conflict by changing a note from a second browser, then see `CONFLICT` and *Overwrite server with mine*.
3. **XSS (T4):** set tag to `<script>alert(1)</script>`; the server rejects it with `XSS_DETECTED` + the indicator `script_tag`.
4. **Cache poisoning (T3):** Tools > verify `/app.js` with hash `deadbeef` -> `DENY HASH_MISMATCH`; with the real hash from `/api/cache-policy` -> `ALLOW`.
5. **Stolen session (T2):** Tools > *Score my current session* -> `REVOKE` with reasons. A real cookie replayed from a different User-Agent is revoked automatically.
6. **Device loss (T5):** Sessions > *I lost a device*; all sessions end. Log in as `admin` > Sessions to see them revoked.
7. As `admin`: change the risk threshold, repeat step 5 (different result), open the audit log, **Verify chain**, **Export CSV**, **Explain** an event.

## 6. Security controls (summary)
bcrypt hashing | server-side sessions (token stored only as SHA-256) with expiry | CSRF header on every write | server-side role checks with generic `Access denied` + audit | login lockout | strict CSP, `nosniff`, `no-store` | parameterized SQL only | server-generated IDs | 128 KB body limit and field limits | stable error codes, no stack traces | secrets redacted from audit | audit table is append-only (DB triggers) and hash-chained | CSV export neutralizes formula injection. See `docs/THREAT_MODEL.md`.

## 7. Limitations and ethics
- Localhost demo only; production hosting, TLS termination, and real attack deployment are out of scope. Set `COOKIE_SECURE=1` behind HTTPS.
- Login rate-limit state is in memory (resets on restart). Risk scoring uses only User-Agent/IP (both spoofable); it is a transparent teaching model, not a full device-binding scheme.
- Losing the notes passphrase means the notes are unrecoverable (by design).
- XSS rules are signature-based and can be bypassed by novel payloads; output is also safe by construction (`textContent`, CSP).
- Demo passwords are public; change them. All test payloads are inert strings used only against this local app. Gemini receives only redacted audit events.

## 8. Troubleshooting / recovery
- *Backend unavailable (502):* start the backend first. *Port in use:* set `FRONTEND_PORT` or edit the uvicorn port in `scripts/run.py`.
- *Reset all data:* stop the servers and delete `data/mobileweb.db*`; it is recreated and re-seeded on start.
- *Service worker stuck:* DevTools > Application > Service Workers > Unregister, then reload.
