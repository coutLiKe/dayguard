"""Recent CVEs from NVD's public feed.

Two filters to keep the signal-to-noise high:
  1. Keywords must match as whole words (regex word boundary), so "python"
     doesn't match "monty pythons" or similar incidental mentions.
  2. CVSS floor (default 7.0). Anything below isn't worth a daily glance.

NVD results are cached for 1 hour so every dashboard refresh doesn't hammer
the API. The cache is busted automatically when the hour expires.

Both NVD and Ollama are free; no API key required for this panel.
"""
import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import httpx
from ..config import CONFIG

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path(__file__).resolve().parent.parent.parent / ".cve_cache.json"
CACHE_TTL_SEC = 60 * 60  # 1 hour


def _read_cve_cache() -> dict | None:
    if not CACHE_PATH.exists():
        return None
    try:
        data = json.loads(CACHE_PATH.read_text())
        if time.time() - data.get("ts", 0) < CACHE_TTL_SEC:
            return data
    except Exception:
        return None
    return None


def _write_cve_cache(payload: dict):
    try:
        CACHE_PATH.write_text(json.dumps({"ts": time.time(), **payload}))
    except Exception:
        pass


def _build_word_patterns(keywords: list[str]) -> list[re.Pattern]:
    return [re.compile(rf"\b{re.escape(k)}\b", re.IGNORECASE) for k in keywords]


async def check_cves() -> dict:
    keywords = CONFIG.get("cve_keywords", [])
    if not keywords:
        return {"severity": "ok", "message": "No CVE keywords configured", "items": []}

    try:
        min_cvss = float(CONFIG.get("cve_min_cvss") or 7.0)
    except (TypeError, ValueError):
        min_cvss = 7.0

    cached = _read_cve_cache()
    if cached:
        return {
            "severity": cached["severity"],
            "message": cached["message"] + " (cached)",
            "items": cached["items"],
        }

    patterns = _build_word_patterns(keywords)

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=48)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(NVD_URL, params=params)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"severity": "ok", "message": f"NVD fetch failed: {e}", "items": []}

    items = []
    severity = "ok"
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        haystack = f"{cve_id} {desc}"
        if not any(p.search(haystack) for p in patterns):
            continue

        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break

        if cvss is None or cvss < min_cvss:
            continue

        items.append({"id": cve_id, "score": cvss, "summary": desc[:240]})
        if cvss >= 9.0:
            severity = "critical"
        elif cvss >= 7.0 and severity != "critical":
            severity = "warn"

    items.sort(key=lambda x: x.get("score") or 0, reverse=True)
    result = {
        "severity": severity,
        "message": f"{len(items)} relevant CVE(s) ≥{min_cvss:.1f} in last 48h",
        "items": items[:10],
    }
    _write_cve_cache(result)
    return result
