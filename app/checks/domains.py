"""SSL certificate + HTTP health checks for user's domains."""
import ssl
import socket
import asyncio
from datetime import datetime, timezone
import httpx
from ..config import CONFIG

_SEV_RANK = {"ok": 0, "warn": 1, "critical": 2}


def _ssl_expiry(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        return {"days_left": days_left, "expires": not_after.isoformat()}
    except Exception as e:
        return {"error": str(e)}


async def _http_check(client: httpx.AsyncClient, url: str) -> dict:
    try:
        r = await client.get(url, follow_redirects=True, timeout=8.0)
        return {"status": r.status_code, "elapsed_ms": int(r.elapsed.total_seconds() * 1000)}
    except Exception as e:
        return {"error": str(e)}


async def _check_one(client: httpx.AsyncClient, d: str) -> dict:
    """Check one domain: SSL and HTTP run concurrently."""
    host = d.replace("https://", "").replace("http://", "").split("/")[0]
    url = f"https://{d}" if not d.startswith("http") else d
    ssl_info, http_info = await asyncio.gather(
        asyncio.to_thread(_ssl_expiry, host),
        _http_check(client, url),
    )
    return {"domain": d, "host": host, "ssl": ssl_info, "http": http_info}


def _item_severity(item: dict) -> str:
    ssl_info = item["ssl"]
    http_info = item["http"]
    if "days_left" in ssl_info:
        if ssl_info["days_left"] < 7:
            return "critical"
        if ssl_info["days_left"] < 14:
            return "warn"
    if "error" in http_info or ("status" in http_info and http_info["status"] >= 500):
        return "critical"
    return "ok"


async def check_domains() -> dict:
    domains = CONFIG.get("domains", [])
    if not domains:
        return {"severity": "warn", "message": "No domains configured", "items": []}

    async with httpx.AsyncClient() as client:
        items = list(await asyncio.gather(*[_check_one(client, d) for d in domains]))

    # Use max-rank to avoid silently downgrading severity across domains.
    severity = max((_item_severity(i) for i in items), key=lambda s: _SEV_RANK[s])

    return {"severity": severity, "message": f"{len(items)} domain(s) checked", "items": items}
