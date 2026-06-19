"""Disk space — main volume only. Warn <15% free, critical <5%."""
import shutil


def check_disk() -> dict:
    try:
        total, used, free = shutil.disk_usage("/")
    except Exception as e:
        return {"severity": "warn", "message": f"disk_usage failed: {e}", "items": []}

    gb = 1024 ** 3
    pct_free = (free / total) * 100 if total else 0

    severity = "ok"
    if pct_free < 5:
        severity = "critical"
    elif pct_free < 15:
        severity = "warn"

    return {
        "severity": severity,
        "message": f"{free/gb:.0f} GB free of {total/gb:.0f} GB ({pct_free:.0f}%)",
        "items": [
            {"label": "Total", "value": f"{total/gb:.0f} GB"},
            {"label": "Used",  "value": f"{used/gb:.0f} GB"},
            {"label": "Free",  "value": f"{free/gb:.0f} GB"},
            {"label": "Free %", "value": f"{pct_free:.1f}%"},
        ],
    }
