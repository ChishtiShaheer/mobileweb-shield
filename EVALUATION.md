# Evaluation Plan and Results

## How to run
```bash
python scripts/setup.py && python scripts/run.py test
```
This also writes `docs/eval_metrics.json` (detection rate, false positives/negatives, decision latency). To capture a log for the report: `python scripts/run.py test > docs/test_log.txt`.

## Acceptance criteria check
| Criterion | Target | How verified |
|---|---|---|
| Functional requirements FR-1..FR-7 demonstrable | all | tests below + demo script in README |
| Automated test pass rate | >= 80% | `pytest` summary (19/19 expected) |
| Unresolved critical authz/injection/secret/file defects | 0 | tests `authorization`, `csrf`, `T4`, audit redaction |
| Rule-based metrics | coverage, FP, FN, latency | `tests/test_engine_metrics.py` -> `docs/eval_metrics.json` |
| Every claim linked to evidence | yes | "Evidence" column below |

## Mandatory cases
| ID | Scenario | Input | Expected result | Evidence (test / manual) | Status |
|---|---|---|---|---|---|
| T1 | Offline/online conflict | edit from stale `base_version=1` after server moved to v2; replay same `op_id` | `conflict` (server copy kept, reason shown); replay -> `duplicate`; DB holds ciphertext only | `test_T1_conflict_duplicate_and_ciphertext_only`; manual: DevTools Offline | PASS (record after your run) |
| T2 | Stolen session | valid cookie replayed with different User-Agent/IP | score 80 >= threshold 50 -> `REVOKE`; later requests 401 `SESSION_REVOKED`; audited | `test_T2_stolen_session` | PASS |
| T3 | Cache poisoning | tampered hash, unlisted path, `/api/*` path vs real hash | `DENY` (HASH_MISMATCH / PATH_NOT_ALLOWLISTED / API_NEVER_CACHED); real hash `ALLOW` | `test_T3_cache_poisoning`, `test_cache_rules_unit` | PASS |
| T4 | XSS | 7 malicious tags (script, onerror, javascript:, iframe, svg onload, entity bypass...) + benign tags | malicious rejected with indicator names; benign applied; no `innerHTML`/`eval` in UI; CSP present | `test_T4_xss_rejected_and_headers`, `test_xss_rule_metrics` | PASS |
| T5 | Device loss | user revokes all sessions; non-admin targets another user | all own sessions 401; other users unaffected; cross-user attempt 403 | `test_T5_device_loss`, `test_remote_revocation_by_admin` | PASS |
| T6 | Responsive accessibility | static HTML/CSS checks + manual checklist | lang, viewport, skip link, labels for every input, live regions, focus style, 44px targets, reduced-motion | `test_T6_accessibility_static` + manual below | PASS (static) / manual pending |
| T-final | Malformed, oversized, unauthorized, repeated, safe failure, restart | invalid JSON, 30 KB ciphertext, huge Content-Length, no cookie, same op x3, DB re-init | 422/413/401 with stable codes; no stack trace; single note created; session survives restart | `test_Tfinal_malformed_oversized_unauth_repeat_restart` | PASS |

### T6 manual checklist (tick and screenshot for the report)
- [ ] Keyboard only: Tab reaches every control, visible focus ring, Skip link works
- [ ] 360 px wide (DevTools device mode): no horizontal page scroll; audit table scrolls inside its box
- [ ] 200% zoom is usable; dark mode readable
- [ ] Lighthouse (Chrome DevTools): Accessibility >= 90, PWA installable check passes
- [ ] Screen reader announces the status line after actions

### Other evidence tests
`test_fr1_pwa_installable_files`, `test_fr2_login_good_bad_and_logout`, `test_login_rate_limit`, `test_csrf_enforced`, `test_authorization_and_generic_denial` (viewer gets generic denial and the attempt is logged), `test_admin_config_change_traceable` (threshold change alters the next decision and is in the audit trail), `test_audit_append_only_and_tamper_evident`, `test_explain_fallback_without_key`, `test_password_policy`.

## Results (fill in after your run)
| Metric | Value |
|---|---|
| Tests passed / total | _/_ (reference run: 19/19) |
| XSS detection rate / false positives | see `docs/eval_metrics.json` (reference: 100% / 0) |
| Avg decision latency (ms) | see `docs/eval_metrics.json` |
| Date, machine, Python version | |

## Known gaps to state in the report
Signature-based XSS rules; in-memory rate limiter; UA/IP-only risk model; static (not automated browser) accessibility checks; Gemini explanations are advisory and not part of any allow/deny decision.
