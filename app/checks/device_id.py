"""Device identification helpers for the Home Network panel.

Three free, fully-local signals turn a bare IP/MAC into something human-readable:

  1. Reverse DNS / mDNS hostname — `socket.gethostbyaddr` resolves Bonjour
     `.local` names and DHCP-assigned hostnames on the LAN. No network call
     leaves your machine; it's the same resolver Finder uses.
  2. MAC vendor (OUI) — the first three octets of a MAC are an IEEE-assigned
     Organizationally Unique Identifier. We ship a curated subset of common
     home-network vendors below (offline, no lookups). Extend freely.
  3. Randomized-MAC detection — modern phones use "private Wi-Fi addresses"
     that rotate per network. These have the locally-administered bit set and
     map to no real vendor, so we label them as private rather than guessing.

None of this touches anything outside your own LAN — it's the same data your
router's admin page shows. See README "Home vs. away networks".
"""
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

# Curated OUI → vendor map. First three octets, uppercase, colon-separated.
# A focused home-network subset — not the full 35k-entry IEEE registry. Add
# prefixes as you spot "unknown" devices you can identify (the panel shows the
# raw MAC, and the OUI is its first three octets).
OUI_VENDORS: dict[str, str] = {
    # Apple
    "00:1B:63": "Apple", "A4:83:E7": "Apple", "AC:DE:48": "Apple",
    "F0:18:98": "Apple", "3C:22:FB": "Apple", "88:66:5A": "Apple",
    "14:7D:DA": "Apple", "7C:D1:C3": "Apple", "D0:81:7A": "Apple",
    # Google / Nest
    "F4:F5:E8": "Google", "54:60:09": "Google", "1C:F2:9A": "Google",
    "6C:AD:F8": "Google", "94:EB:2C": "Google", "3C:5A:B4": "Google",
    # Amazon (Echo, Fire, Ring)
    "0C:47:C9": "Amazon", "44:65:0D": "Amazon", "F0:27:2D": "Amazon",
    "68:54:FD": "Amazon", "FC:65:DE": "Amazon", "74:C2:46": "Amazon",
    "AC:63:BE": "Amazon",
    # Samsung
    "00:12:FB": "Samsung", "5C:0A:5B": "Samsung", "8C:77:12": "Samsung",
    "78:1F:DB": "Samsung", "F8:04:2E": "Samsung", "38:01:97": "Samsung",
    "BC:14:85": "Samsung",
    # Xiaomi
    "28:6C:07": "Xiaomi", "64:09:80": "Xiaomi", "78:11:DC": "Xiaomi",
    "F8:A4:5F": "Xiaomi", "50:8F:4C": "Xiaomi", "34:CE:00": "Xiaomi",
    # Microsoft (incl. Hyper-V virtual NICs)
    "00:15:5D": "Microsoft", "28:18:78": "Microsoft", "7C:1E:52": "Microsoft",
    "60:45:BD": "Microsoft", "C8:3F:26": "Microsoft",
    # Intel
    "00:1B:21": "Intel", "3C:97:0E": "Intel", "7C:7A:91": "Intel",
    "A0:88:B4": "Intel", "34:13:E8": "Intel", "8C:55:4A": "Intel",
    # Dell
    "00:14:22": "Dell", "B8:CA:3A": "Dell", "F8:BC:12": "Dell",
    "18:66:DA": "Dell", "84:7B:EB": "Dell",
    # HP
    "00:1B:78": "HP", "3C:D9:2B": "HP", "70:5A:0F": "HP",
    "9C:B6:54": "HP", "A0:48:1C": "HP",
    # Routers / network gear
    "50:C7:BF": "TP-Link", "AC:84:C6": "TP-Link", "60:32:B1": "TP-Link",
    "EC:08:6B": "TP-Link", "14:CC:20": "TP-Link",
    "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti", "68:D7:9A": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
    "00:14:6C": "Netgear", "20:E5:2A": "Netgear", "A0:40:A0": "Netgear",
    "9C:3D:CF": "Netgear", "28:C6:8E": "Netgear", "C0:3F:0E": "Netgear",
    "00:18:0A": "Cisco Meraki", "E0:CB:BC": "Cisco", "88:15:44": "Cisco",
    "F8:BB:BF": "eero", "B8:5F:98": "eero",
    # Smart home / media
    "00:0E:58": "Sonos", "34:7E:5C": "Sonos", "48:A6:B8": "Sonos",
    "5C:AA:FD": "Sonos", "78:28:CA": "Sonos", "94:9F:3E": "Sonos",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue", "00:0D:14": "Philips",
    "B0:A7:37": "Roku", "CC:6D:A0": "Roku", "AC:3A:7A": "Roku",
    "D8:31:34": "Roku", "DC:3A:5E": "Roku",
    "2C:AA:8E": "Wyze", "7C:78:B2": "Wyze",
    # Gaming / consoles
    "00:09:BF": "Nintendo", "0C:FE:45": "Nintendo", "58:BD:A3": "Nintendo",
    "98:B6:E9": "Nintendo", "E8:4E:CE": "Nintendo", "8C:CD:E8": "Nintendo",
    "00:13:A9": "Sony", "30:F9:ED": "Sony", "FC:0F:E6": "Sony", "A0:E4:53": "Sony",
    "00:1C:62": "LG", "00:1E:75": "LG", "A8:23:FE": "LG", "C4:36:6C": "LG",
    # Maker / IoT boards
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "24:0A:C4": "Espressif (ESP)", "30:AE:A4": "Espressif (ESP)",
    "A4:CF:12": "Espressif (ESP)", "7C:9E:BD": "Espressif (ESP)",
    "EC:FA:BC": "Espressif (ESP)",
    # NAS
    "00:11:32": "Synology", "90:09:D0": "Synology", "24:5E:BE": "Synology",
}


def is_multicast_mac(mac: str) -> bool:
    """True for multicast/broadcast MACs (e.g. ff:ff:ff:ff:ff:ff broadcast or
    01:00:5e:* mDNS). These are network infrastructure addresses, not real
    devices, and should be filtered out of the device list."""
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    # Bit 0 (value 0x01) of the first octet = group (multicast) address.
    return bool(first_octet & 0x01)


def is_randomized_mac(mac: str) -> bool:
    """True if the MAC is locally administered (the bit phones flip for
    private Wi-Fi addresses). These rotate per network and map to no vendor."""
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    # Bit 1 (value 0x02) of the first octet = locally administered.
    return bool(first_octet & 0x02)


def vendor_for_mac(mac: str) -> str | None:
    """Look up the manufacturer from the MAC's OUI prefix. None if unknown
    or randomized (a randomized MAC's prefix is meaningless)."""
    if is_randomized_mac(mac):
        return None
    return OUI_VENDORS.get(mac.upper()[:8])


def _resolve_one(ip: str) -> str | None:
    """Reverse-DNS / mDNS lookup for a single IP. Strips the trailing dot and
    a `.local`/`.lan` suffix for a cleaner label. None if it doesn't resolve."""
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    if not host:
        return None
    host = host.rstrip(".")
    for suffix in (".local", ".lan", ".home"):
        if host.lower().endswith(suffix):
            host = host[: -len(suffix)]
            break
    return host or None


def resolve_hostnames(ips: list[str], timeout: float = 2.0) -> dict[str, str]:
    """Resolve a batch of IPs to hostnames in parallel. Each lookup is capped
    at `timeout` seconds so a non-responsive device can't stall the panel;
    unresolved IPs are simply omitted from the result."""
    results: dict[str, str] = {}
    if not ips:
        return results
    with ThreadPoolExecutor(max_workers=min(8, len(ips))) as ex:
        futures = {ex.submit(_resolve_one, ip): ip for ip in ips}
        for fut, ip in futures.items():
            try:
                name = fut.result(timeout=timeout)
            except (FuturesTimeout, Exception):
                name = None
            if name:
                results[ip] = name
    return results
