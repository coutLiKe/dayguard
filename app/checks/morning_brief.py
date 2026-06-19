"""Local-LLM morning brief via Ollama.

Sends a structured summary of all panels to a local model and gets back a
short narrative. Cached for 4 hours so we don't hammer Ollama on every refresh.
Falls back to a deterministic message if Ollama isn't reachable.

The greeting ("Good morning/afternoon/evening") is computed fresh on every
request and prepended to the cached body — so a brief generated at 11am still
greets you correctly when you reopen the dashboard at 6pm. The body itself is
greeting-free in the cache.
"""
import json
import time
from datetime import datetime
from pathlib import Path
import httpx
from ..config import CONFIG

CACHE_PATH = Path(__file__).resolve().parent.parent.parent / ".brief_cache.json"
CACHE_TTL_SEC = 4 * 60 * 60  # 4 hours

_GREETINGS = {
    "morning": "Good morning",
    "afternoon": "Good afternoon",
    "evening": "Good evening",
}


def _period(now: datetime | None = None) -> str:
    """Time-of-day bucket from the local clock. Server runs on the user's Mac,
    so datetime.now() is their local time."""
    hour = (now or datetime.now()).hour
    if hour < 12:
        return "morning"
    if hour < 17:
        return "afternoon"
    return "evening"


def _greeting(now: datetime | None = None) -> str:
    return _GREETINGS[_period(now)]


def _compose(greeting: str, body: str) -> str:
    """Prepend the fresh greeting to a greeting-free brief body."""
    body = (body or "").strip()
    return f"{greeting}. {body}" if body else f"{greeting}."


def _severity_sig(panels: dict) -> str:
    """Compact string of panel severities — used to bust the cache when posture changes."""
    return "|".join(f"{k}:{p.get('severity', 'ok')}" for k, p in sorted(panels.items()))


def _read_cache(panels: dict) -> dict | None:
    if not CACHE_PATH.exists():
        return None
    try:
        data = json.loads(CACHE_PATH.read_text())
        if time.time() - data.get("ts", 0) < CACHE_TTL_SEC:
            if data.get("sig") == _severity_sig(panels):
                return data
    except Exception:
        return None
    return None


def _write_cache(text: str, model: str, panels: dict):
    try:
        CACHE_PATH.write_text(json.dumps({
            "ts": time.time(), "text": text, "model": model,
            "sig": _severity_sig(panels),
        }))
    except Exception:
        pass


def _summarize_panels_for_prompt(panels: dict) -> str:
    """Compact, LLM-friendly snapshot of current state."""
    lines = []
    for key, p in panels.items():
        sev = p.get("severity", "ok")
        msg = (p.get("message") or "").strip()
        lines.append(f"- {key} [{sev}]: {msg}")
        items = p.get("items", [])
        for it in items[:3]:
            # Pull a compact one-liner from each item
            if isinstance(it, dict):
                summary = it.get("name") or it.get("domain") or it.get("id") or it.get("ip") or it.get("type") or it.get("label") or ""
                detail = it.get("detail") or it.get("summary") or it.get("error") or ""
                if summary or detail:
                    lines.append(f"    · {summary} {('— ' + str(detail)) if detail else ''}")
    return "\n".join(lines)


async def morning_brief(panels: dict) -> dict:
    # Greeting is computed fresh every call (never cached) so it always matches
    # the current time of day.
    period = _period()
    greeting = _GREETINGS[period]

    cached = _read_cache(panels)
    if cached:
        return {
            "severity": "ok",
            "message": "Brief (cached)",
            "text": _compose(greeting, cached["text"]),
            "model": cached.get("model", "?"),
            "cached": True,
            "period": period,
        }

    base_url = CONFIG.get("ollama_url", "http://localhost:11434")
    model = CONFIG.get("ollama_model", "llama3.2:3b")

    snapshot = _summarize_panels_for_prompt(panels)
    prompt = (
        "You are DayGuard, a calm personal-security assistant. "
        "Given today's signals from a Mac, write a 2-3 sentence brief in plain English. "
        "Do not open with a greeting (no 'Good morning' etc.) — a greeting is added separately, "
        "so start directly with the substance. "
        "Lead with what (if anything) needs the user's attention. If everything looks fine, say so plainly. "
        "No emoji, no markdown, no headings. Conversational tone, like a thoughtful colleague.\n\n"
        f"Signals:\n{snapshot}\n\n"
        "Brief:"
    )

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(
                f"{base_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
        r.raise_for_status()
        data = r.json()
        text = (data.get("response") or "").strip()
        if not text:
            raise ValueError("empty response from ollama")
    except Exception as e:
        return {
            "severity": "warn",
            "message": "Ollama unreachable — showing fallback brief",
            "text": _compose(greeting, _fallback_brief(panels)),
            "model": "fallback",
            "cached": False,
            "period": period,
            "error": str(e),
        }

    # Cache the greeting-free body; the greeting is prepended at serve time.
    _write_cache(text, model, panels)
    return {
        "severity": "ok",
        "message": f"Brief generated by {model}",
        "text": _compose(greeting, text),
        "model": model,
        "cached": False,
        "period": period,
    }


def _fallback_brief(panels: dict) -> str:
    sev_counts = {"ok": 0, "warn": 0, "critical": 0}
    issues = []
    for key, p in panels.items():
        s = p.get("severity", "ok")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        if s != "ok":
            issues.append(f"{key} ({s})")
    if sev_counts["critical"]:
        return f"You have {sev_counts['critical']} critical and {sev_counts['warn']} warning panel(s): {', '.join(issues)}. Open the dashboard to act on these."
    if sev_counts["warn"]:
        return f"Everything's mostly fine — {sev_counts['warn']} panel(s) want a look when you have a minute: {', '.join(issues)}."
    return "All quiet right now. Every panel is reporting normal status."
