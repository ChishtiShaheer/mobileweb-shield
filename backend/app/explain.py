"""Gemini explanations of (already redacted) audit events, with model fallback and offline rule-based fallback."""
import os
from . import config

# Google retires model names over time, so the model is configurable (GEMINI_MODEL in .env).
CANDIDATES = [m for m in [os.environ.get("GEMINI_MODEL", "").strip(), "gemini-3.5-flash", "gemini-2.5-flash"] if m]

def explain_event(ev: dict) -> dict:
    fallback = (f"Rule-based summary: action {ev['action']} by {ev['actor']} ({ev['role']}) ended with "
                f"outcome {ev['outcome']}. Details: {ev['detail']}")
    if not config.GEMINI_API_KEY:
        return {"source": "rule-based", "text": fallback + " (set GEMINI_API_KEY in .env for AI explanations)"}
    prompt = ("You are a security analyst assistant. In at most 4 sentences, explain this audit event to a "
              "reviewer: what happened, why it matters, and the recommended action. Do not invent facts.\n"
              f"Event: {ev}")
    errors = []
    try:
        from google import genai
        client = genai.Client(api_key=config.GEMINI_API_KEY)
    except Exception as e:
        return {"source": "rule-based", "text": fallback + f" (Gemini client error: {type(e).__name__})"}
    for model in dict.fromkeys(CANDIDATES):
        try:
            out = client.models.generate_content(model=model, contents=prompt)
            if out.text: return {"source": model, "text": out.text.strip()}
        except Exception as e:
            errors.append(f"{model}: {type(e).__name__} {str(e)[:100]}".replace(config.GEMINI_API_KEY, "***"))
    return {"source": "rule-based", "text": fallback + " (Gemini failed: " + " | ".join(errors) + ")"}