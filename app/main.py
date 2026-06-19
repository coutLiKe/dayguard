"""DayGuard — personal security dashboard.

Run: uvicorn app.main:app --host 127.0.0.1 --port 8765
Then open http://localhost:8765
"""
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .checks.domains import check_domains
from .checks.cves import check_cves
from .checks.network import check_network
from .checks.macos import check_macos
from .checks.vpn import check_vpn
from .checks.disk import check_disk
from .checks.apps import check_apps
from .checks.morning_brief import morning_brief

app = FastAPI(title="DayGuard", version="0.3.2")
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Per-panel timeout (seconds). If any check exceeds this, /api/summary still
# returns; the slow panel gets a degraded payload instead of hanging the page.
PANEL_TIMEOUT_SEC = 15


async def _safe(name: str, coro, timeout: int = PANEL_TIMEOUT_SEC) -> dict:
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        return {"severity": "warn", "message": f"{name} timed out after {timeout}s", "items": []}
    except Exception as e:
        return {"severity": "warn", "message": f"{name}: {type(e).__name__}: {e}", "items": []}


@app.get("/")
async def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    # Stop the 404 log noise; serve a real icon later if we make one.
    from fastapi.responses import Response
    return Response(status_code=204)


@app.get("/api/health")
async def health():
    return {"ok": True, "ts": datetime.now(timezone.utc).isoformat()}


@app.get("/api/panel/domains")
async def panel_domains(): return await _safe("domains", check_domains())

@app.get("/api/panel/cves")
async def panel_cves(): return await _safe("cves", check_cves())

@app.get("/api/panel/network")
async def panel_network(): return await _safe("network", asyncio.to_thread(check_network))

@app.get("/api/panel/macos")
async def panel_macos(): return await _safe("macos", asyncio.to_thread(check_macos), timeout=30)

@app.get("/api/panel/vpn")
async def panel_vpn(): return await _safe("vpn", asyncio.to_thread(check_vpn))

@app.get("/api/panel/disk")
async def panel_disk(): return await _safe("disk", asyncio.to_thread(check_disk))

@app.get("/api/panel/apps")
async def panel_apps(): return await _safe("apps", asyncio.to_thread(check_apps))


@app.get("/api/summary")
async def summary():
    macos_co   = _safe("macos",   asyncio.to_thread(check_macos), timeout=30)
    network_co = _safe("network", asyncio.to_thread(check_network))
    vpn_co     = _safe("vpn",     asyncio.to_thread(check_vpn))
    disk_co    = _safe("disk",    asyncio.to_thread(check_disk))
    apps_co    = _safe("apps",    asyncio.to_thread(check_apps))
    domains_co = _safe("domains", check_domains())
    cves_co    = _safe("cves",    check_cves())

    mac, network, vpn, disk, apps_, domains, cves = await asyncio.gather(
        macos_co, network_co, vpn_co, disk_co, apps_co, domains_co, cves_co
    )

    panels = {
        "macos": mac, "network": network, "vpn": vpn, "disk": disk, "apps": apps_,
        "domains": domains, "cves": cves,
    }

    brief = await morning_brief(panels)

    sev_rank = {"ok": 0, "warn": 1, "critical": 2}
    overall = max(panels.values(), key=lambda p: sev_rank.get(p.get("severity", "ok"), 0))

    return {
        "overall_severity": overall.get("severity", "ok"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "brief": brief,
        "panels": panels,
    }
