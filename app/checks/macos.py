"""macOS security posture.

FileVault, firewall, Gatekeeper, SIP, software updates, failed auth, Time Machine.

Two tiers:
  * Hard checks (FileVault, Firewall, Gatekeeper, SIP, Failed Auth) drive
    panel severity. A failure here means something is actually wrong.
  * Informational checks (Software Updates, Time Machine) are shown in the
    detail rows but don't bump severity — they reflect personal preference
    (update cadence, backup tool choice) more than security failure.

`softwareupdate -l` can block for 10-30 seconds, so it's cached for 24h in a
small JSON file. Other commands return in well under a second.
"""
import json
import subprocess
import time
from pathlib import Path

CACHE_PATH = Path(__file__).resolve().parent.parent.parent / ".macos_cache.json"
UPDATES_CACHE_TTL_SEC = 24 * 60 * 60

HARD_CHECK_NAMES = {"FileVault", "Firewall", "Gatekeeper", "SIP", "Failed Auth (24h)"}
CRITICAL_FAIL_NAMES = {"FileVault", "SIP"}


def _run(cmd: list[str], timeout: int = 6) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=timeout).strip()
    except Exception as e:
        return f"error: {e}"


def _cached_updates_check() -> tuple[bool, str]:
    cached = None
    if CACHE_PATH.exists():
        try:
            data = json.loads(CACHE_PATH.read_text())
            if time.time() - data.get("ts", 0) < UPDATES_CACHE_TTL_SEC:
                cached = data
        except Exception:
            pass
    if cached:
        return cached["pending"], cached["label"]

    out = _run(["softwareupdate", "-l"], timeout=25)
    pending = "No new software available" not in out and "no new software" not in out.lower()
    label = "Updates pending" if pending else "Up to date"
    try:
        CACHE_PATH.write_text(json.dumps({"ts": time.time(), "pending": pending, "label": label}))
    except Exception:
        pass
    return pending, label


def _time_machine_status() -> dict:
    """Returns a check dict for Time Machine. Treats 'not configured' as a
    deliberate choice, not a failure."""
    tm = _run(["tmutil", "latestbackup"], timeout=5)
    low = tm.lower()

    if "no machine destination" in low or "no destinations" in low or "must specify" in low:
        return {"name": "Time Machine", "ok": True, "info": True, "detail": "Not configured"}
    if tm.startswith("error:") or "error" in low:
        return {"name": "Time Machine", "ok": True, "info": True, "detail": tm.split(":", 1)[-1].strip()[:42]}
    if "/" in tm:
        return {"name": "Time Machine", "ok": True, "info": True, "detail": tm.split("/")[-1]}
    return {"name": "Time Machine", "ok": True, "info": True, "detail": "Unknown"}


def check_macos() -> dict:
    checks = []

    fv = _run(["fdesetup", "status"])
    checks.append({"name": "FileVault", "ok": "FileVault is On" in fv,
                   "detail": fv.splitlines()[0] if fv else ""})

    fw = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    checks.append({"name": "Firewall", "ok": "enabled" in fw.lower() and "disabled" not in fw.lower(),
                   "detail": fw})

    gk = _run(["spctl", "--status"])
    checks.append({"name": "Gatekeeper", "ok": "assessments enabled" in gk, "detail": gk})

    sip = _run(["csrutil", "status"])
    checks.append({"name": "SIP", "ok": "enabled" in sip.lower() and "disabled" not in sip.lower(),
                   "detail": sip.splitlines()[0] if sip else ""})

    failed = _run(["log", "show", "--predicate",
                   'eventMessage CONTAINS "authentication failure"',
                   "--last", "24h", "--style", "compact"], timeout=10)
    failed_count = len([ln for ln in failed.splitlines() if "authentication" in ln.lower()])
    checks.append({"name": "Failed Auth (24h)", "ok": failed_count < 5,
                   "detail": f"{failed_count} attempts"})

    # Informational checks — don't drive severity, just inform.
    pending, label = _cached_updates_check()
    checks.append({"name": "Software Updates", "ok": not pending, "info": True, "detail": label})
    checks.append(_time_machine_status())

    # Severity is driven only by HARD failures.
    hard_failing = [c for c in checks if not c["ok"] and c["name"] in HARD_CHECK_NAMES]
    if any(c["name"] in CRITICAL_FAIL_NAMES for c in hard_failing):
        severity = "critical"
    elif hard_failing:
        severity = "warn"
    else:
        severity = "ok"

    passing = sum(1 for c in checks if c["ok"])
    return {
        "severity": severity,
        "message": f"{passing}/{len(checks)} checks passing",
        "items": checks,
    }
