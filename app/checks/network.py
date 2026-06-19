"""LAN device scan via `arp -a`. Avoids root-required nmap for the MVP.

Home-aware: if `home_gateway_macs` is set in config.json, we compare the
current default gateway's MAC against it. On your home network, unknown
devices raise severity as before. On any other network (cafe, office,
hotspot), the scan is informational only — there will always be strangers
on a public LAN, and that's not *your* security problem.
"""
import re
import subprocess
from ..config import CONFIG
from .device_id import (
    resolve_hostnames, vendor_for_mac, is_randomized_mac, is_multicast_mac,
)

_ARP_PATTERN = re.compile(
    r"\((?P<ip>[\d.]+)\) at (?P<mac>[0-9a-fA-F:]{11,17})", re.MULTILINE
)


def _normalize_mac(mac: str) -> str:
    """macOS prints short octets (a:b:c:d:e:f) — pad to standard form."""
    return ":".join(p.zfill(2) for p in mac.lower().split(":"))


def _default_gateway_ip() -> str | None:
    try:
        out = subprocess.check_output(["route", "-n", "get", "default"],
                                      text=True, timeout=5)
    except Exception:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            return line.split(":", 1)[1].strip()
    return None


def check_network() -> dict:
    known = {_normalize_mac(d["mac"]): d.get("name", "unknown")
             for d in CONFIG.get("known_devices", [])}
    home_gateways = {_normalize_mac(m) for m in CONFIG.get("home_gateway_macs", [])}

    try:
        out = subprocess.check_output(["arp", "-a"], text=True, timeout=8)
    except Exception as e:
        return {"severity": "warn", "message": f"arp failed: {e}", "items": []}

    gateway_ip = _default_gateway_ip()
    gateway_mac = None

    # First pass: parse ARP into raw (ip, mac) pairs. Skip broadcast/multicast
    # rows (255.255.255.255, 224.0.0.x, ff:ff:ff:..) — they're not devices.
    parsed = []
    for m in _ARP_PATTERN.finditer(out):
        mac_full = _normalize_mac(m.group("mac"))
        ip = m.group("ip")
        if is_multicast_mac(mac_full):
            continue
        if gateway_ip and ip == gateway_ip:
            gateway_mac = mac_full
        parsed.append((ip, mac_full))

    # Resolve hostnames for every IP in parallel (one batched, time-capped pass).
    hostnames = resolve_hostnames([ip for ip, _ in parsed])

    # Second pass: build display records. A device is "known" only if its MAC
    # is in config — that's the security signal. Hostname/vendor just make
    # unrecognized devices identifiable instead of a bare "Unknown".
    devices = []
    stable_unknown = 0   # unrecognized devices with a real (non-randomized) MAC
    private_count = 0    # randomized/private MACs — expected churn, informational
    for ip, mac_full in parsed:
        configured = known.get(mac_full)
        is_known = configured is not None

        hostname = hostnames.get(ip)
        vendor = vendor_for_mac(mac_full)
        randomized = is_randomized_mac(mac_full)

        if not is_known:
            if randomized:
                private_count += 1
            else:
                stable_unknown += 1

        if configured:
            name = configured
        elif hostname:
            name = hostname
        elif vendor:
            name = f"{vendor} device"
        elif randomized:
            name = "Private (randomized MAC)"
        else:
            name = "Unknown"

        is_gateway = bool(gateway_ip and ip == gateway_ip)
        devices.append({
            "ip": ip,
            "mac": mac_full,
            "name": name,
            "known": is_known,
            "hostname": hostname,
            "vendor": vendor,
            "randomized": randomized,
            "gateway": is_gateway,
        })

    # Determine where we are. Three cases:
    #   at_home=True   — gateway matches a configured home gateway
    #   at_home=False  — gateways configured, current one doesn't match
    #   at_home=None   — feature unconfigured (or gateway undetectable): old behavior
    at_home: bool | None = None
    if home_gateways and gateway_mac:
        at_home = gateway_mac in home_gateways

    # Randomized/private MACs rotate per-network and are ubiquitous on modern
    # phones, so they're informational only. Severity is driven solely by
    # STABLE unidentified devices — a persistent real-vendor MAC you haven't
    # named is the actual "stranger on my LAN" signal.
    def _count_phrase() -> str:
        bits = [f"{len(devices)} device(s)"]
        if stable_unknown:
            bits.append(f"{stable_unknown} unidentified")
        if private_count:
            bits.append(f"{private_count} private")
        return " · ".join(bits)

    if at_home is False:
        severity = "ok"
        message = f"Away from home — {_count_phrase()} (informational)"
    else:
        severity = "ok"
        if stable_unknown > 0:
            severity = "warn" if stable_unknown <= 2 else "critical"
        message = _count_phrase()
        if at_home is True:
            message = "Home network — " + message

    return {
        "severity": severity,
        "message": message,
        "items": devices,
        "meta": {
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "at_home": at_home,
            "stable_unknown": stable_unknown,
            "private_count": private_count,
        },
    }
