"""VPN / tunnel detection.

Two sources combined:
  - `scutil --nc list`  — system-configured VPNs (IKEv2/IPSec, L2TP, IPsec, AnyConnect)
  - `ifconfig` utun     — filtered to skip Apple's iCloud Private Relay tunnels
                           (utun0/1/2 with link-local IPv6) and Personal Hotspot

Severity is always "ok" — VPN is opt-in, so "not connected" is informational
not alarming. The dashboard reports what's active, doesn't nag.
"""
import subprocess


def _real_tunnels() -> list[dict]:
    """utun interfaces with a non-link-local IPv4 address."""
    tunnels = []
    try:
        out = subprocess.check_output(["ifconfig"], text=True, timeout=5)
    except Exception:
        return tunnels

    cur = None
    cur_ipv4 = None
    for line in out.splitlines():
        if line and not line.startswith("\t"):
            if cur and cur.startswith("utun") and cur_ipv4:
                tunnels.append({"name": cur, "type": "tunnel", "connected": True, "ip": cur_ipv4})
            cur = line.split(":")[0]
            cur_ipv4 = None
        elif cur and cur.startswith("utun") and line.strip().startswith("inet "):
            parts = line.strip().split(" ")
            ip = parts[1] if len(parts) > 1 else ""
            # Skip Apple's link-local / private-relay style addresses
            if ip and not ip.startswith("169.254.") and not ip.startswith("fe80"):
                cur_ipv4 = ip
    # tail
    if cur and cur.startswith("utun") and cur_ipv4:
        tunnels.append({"name": cur, "type": "tunnel", "connected": True, "ip": cur_ipv4})
    return tunnels


def _system_vpns() -> list[dict]:
    """Parse `scutil --nc list` for system-configured VPNs."""
    out = []
    try:
        raw = subprocess.check_output(["scutil", "--nc", "list"], text=True, timeout=5)
    except Exception as e:
        return [{"error": f"scutil failed: {e}"}]
    for line in raw.splitlines():
        line = line.rstrip()
        if not line or "VPN Configurations" in line:
            continue
        connected = "(Connected)" in line
        name = line.split("\"")[1] if "\"" in line else line[-40:].strip()
        kind = "IKEv2/IPSec" if "IPSec" in line else ("L2TP" if "L2TP" in line else "VPN")
        out.append({"name": name, "type": kind, "connected": connected})
    return out


def check_vpn() -> dict:
    items = _system_vpns() + _real_tunnels()
    errors = [i for i in items if "error" in i]
    real = [i for i in items if "error" not in i]
    active = [i for i in real if i.get("connected")]

    if errors and not real:
        message = f"VPN detection failed ({errors[0].get('error','?')[:60]})"
    elif not real:
        message = "No VPN configured"
    elif not active:
        message = f"{len(real)} VPN(s) configured, none connected"
    else:
        message = f"{len(active)} VPN/tunnel(s) active"

    # VPN is opt-in. Never raise severity for "not connected" — that's the user's choice.
    return {"severity": "ok", "message": message, "items": items}
