"""Rule-based metrics: coverage, false positives/negatives, decision latency -> docs/eval_metrics.json"""
import json, time
from pathlib import Path
from app import security_engine as eng

ROOT = Path(__file__).resolve().parents[1]
S = json.loads((ROOT / "tests/fixtures/samples.json").read_text())

def test_xss_rule_metrics():
    fp = [t for t in S["benign_tags"] if not eng.scan_text(t)["safe"]]
    fn = [t for t in S["malicious_tags"] if eng.scan_text(t)["safe"]]
    t0 = time.perf_counter()
    for t in S["benign_tags"] + S["malicious_tags"]: eng.scan_text(t)
    lat_ms = (time.perf_counter() - t0) * 1000 / (len(S["benign_tags"]) + len(S["malicious_tags"]))
    m = {"rules": len(eng.XSS_RULES), "benign_samples": len(S["benign_tags"]), "malicious_samples": len(S["malicious_tags"]),
         "false_positives": fp, "false_negatives": fn, "detection_rate": 1 - len(fn) / len(S["malicious_tags"]),
         "avg_decision_latency_ms": round(lat_ms, 4)}
    (ROOT / "docs" / "eval_metrics.json").write_text(json.dumps(m, indent=2))
    assert not fp and not fn and lat_ms < 5

def test_password_policy():
    assert eng.check_password_policy("Short1") and not eng.check_password_policy("Longenough123")

def test_cache_rules_unit():
    man = {"assets": {"/a.js": "abc"}}
    assert eng.verify_cache_entry("/a.js", "abc", man)["decision"] == "ALLOW"
    assert eng.verify_cache_entry("/a.js", "bad", man)["rule"] == "HASH_MISMATCH"
    assert eng.verify_cache_entry("/api/x", "abc", man)["rule"] == "API_NEVER_CACHED"
