"""Apps added or modified in /Applications within the last N days.

Optional: runs `codesign -dv` to flag unsigned bundles.
"""
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

APPS_DIR = Path("/Applications")
LOOKBACK_DAYS = 7


def _is_signed(app_path: Path) -> bool | None:
    try:
        r = subprocess.run(
            ["codesign", "-dv", str(app_path)],
            capture_output=True, text=True, timeout=4,
        )
        # codesign returns 0 if signed; non-zero if unsigned/invalid
        return r.returncode == 0
    except Exception:
        return None


def check_apps() -> dict:
    if not APPS_DIR.exists():
        return {"severity": "warn", "message": "/Applications not found", "items": []}

    cutoff = time.time() - LOOKBACK_DAYS * 86400
    now = time.time()

    # First pass: collect candidates without doing the expensive codesign call.
    candidates = []
    for entry in APPS_DIR.iterdir():
        if not entry.name.endswith(".app"):
            continue
        try:
            mtime = entry.stat().st_mtime
        except Exception:
            continue
        if mtime >= cutoff:
            candidates.append((entry, mtime))

    # Second pass: codesign in parallel so 20 apps takes ~2s, not 20s.
    paths = [c[0] for c in candidates]
    signed_results = []
    if paths:
        with ThreadPoolExecutor(max_workers=8) as ex:
            signed_results = list(ex.map(_is_signed, paths))

    recent = []
    for (entry, mtime), signed in zip(candidates, signed_results):
        recent.append({
            "name": entry.name.replace(".app", ""),
            "modified_days_ago": round((now - mtime) / 86400, 1),
            "signed": signed,
        })

    recent.sort(key=lambda x: x["modified_days_ago"])

    unsigned = [a for a in recent if a["signed"] is False]
    severity = "warn" if unsigned else "ok"
    message = f"{len(recent)} app(s) installed/updated in last {LOOKBACK_DAYS}d"
    if unsigned:
        message += f" — {len(unsigned)} unsigned"

    return {"severity": severity, "message": message, "items": recent[:20]}
