"""Gemini 2.5 Flash explanations of (already redacted) audit events, with offline fallback."""
from . import config

MODEL = "gemini-2.5-flash"

def explain_event(ev: dict) -> dict:
    fallback = (f"Rule-based summary: action {ev['action']} by {ev['actor']} ({ev['role']}) ended with "
                f"outcome {ev['outcome']}. Details: {ev['detail']}")
    if not config.GEMINI_API_KEY:
        return {"source": "rule-based", "text": fallback + " (set GEMINI_API_KEY for AI explanations)"}
    try:
        from google import genai
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        prompt = ("You are a security analyst assistant. In at most 4 sentences, explain this audit event to a "
                  "reviewer: what happened, why it matters, and the recommended action. Do not invent facts.\n"
                  f"Event: {ev}")
        out = client.models.generate_content(model=MODEL, contents=prompt)
        return {"source": MODEL, "text": (out.text or fallback).strip()}
    except Exception:
        return {"source": "rule-based", "text": fallback + " (Gemini unavailable)"}
