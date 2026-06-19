"""DayGuard menu bar companion.

Runs as a separate process from the FastAPI server. Polls /api/summary on a
rumps.Timer (main-thread, AppKit-safe), shows a colored dot in the menu bar,
and fires native macOS notifications when severity escalates.

Run: python3 menubar.py
"""
import json
import os
import subprocess
import threading
import time
import webbrowser
from pathlib import Path

import rumps
import httpx

# ---- Configuration ----
DASHBOARD_URL = "http://localhost:8765"
SUMMARY_URL = f"{DASHBOARD_URL}/api/summary"
HEALTH_URL = f"{DASHBOARD_URL}/api/health"
POLL_INTERVAL_SEC = 5 * 60
STATE_PATH = Path(__file__).parent / ".menubar_state.json"
BACKEND_LABEL = "com.kevinlin.dayguard"
# Don't auto-restart the backend more often than this (seconds)
RESTART_COOLDOWN_SEC = 60

DOT = {
    "ok": "🟢",
    "warn": "🟡",
    "critical": "🔴",
    "offline": "⚪",
}

PANEL_LABELS = {
    "macos": "macOS Posture",
    "network": "Home Network",
    "vpn": "VPN & Tunnels",
    "disk": "Disk Space",
    "apps": "Recent App Changes",
    "domains": "Domain & SSL",
    "cves": "Recent CVEs",
}


def _notify(title: str, subtitle: str, message: str):
    """Native macOS notification via osascript (avoids rumps' bundle-id issues)."""
    # osascript needs us to escape double-quotes in the strings we pass.
    def _q(s: str) -> str:
        return s.replace('\\', '\\\\').replace('"', '\\"')
    try:
        script = (
            f'display notification "{_q(message)}" '
            f'with title "{_q(title)}" subtitle "{_q(subtitle)}"'
        )
        subprocess.run(["osascript", "-e", script], check=False, timeout=4)
    except Exception:
        pass


def _kickstart_backend() -> bool:
    """Ask launchd to (re)start the backend service. Returns True if the
    command was accepted. No-op if the LaunchAgent isn't installed."""
    try:
        r = subprocess.run(
            ["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{BACKEND_LABEL}"],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


def _backend_alive(timeout: float = 3.0) -> bool:
    try:
        with httpx.Client(timeout=timeout) as client:
            return client.get(HEALTH_URL).status_code == 200
    except Exception:
        return False


def _load_last_state() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text())
    except Exception:
        return {}


def _save_state(state: dict):
    try:
        STATE_PATH.write_text(json.dumps(state))
    except Exception:
        pass


class DayGuardMenu(rumps.App):
    def __init__(self):
        super().__init__("DayGuard", title=DOT["offline"], quit_button=None)

        # Build menu items ONCE with stable references. We update their titles
        # in place on each poll — never rebuild the menu structure.
        self.status_item = rumps.MenuItem("Status: starting…")
        # Give panel items a callback so rumps renders them enabled (not greyed).
        # Clicking any panel row opens the dashboard.
        self.panel_items = {
            key: rumps.MenuItem(label, callback=self.open_dashboard)
            for key, label in PANEL_LABELS.items()
        }

        self.menu = [
            self.status_item,
            None,
            *self.panel_items.values(),
            None,
            rumps.MenuItem("Open Dashboard", callback=self.open_dashboard),
            rumps.MenuItem("Refresh now", callback=self.refresh_now),
            rumps.MenuItem("Restart Backend", callback=self.restart_backend),
            None,
            rumps.MenuItem("Quit DayGuard", callback=rumps.quit_application),
        ]

        self.last_state = _load_last_state()
        self._last_restart_attempt = 0.0

        # rumps.Timer fires on the main thread — safe to mutate menu items.
        self.timer = rumps.Timer(self._tick, POLL_INTERVAL_SEC)
        self.timer.start()
        # Kick off an immediate first poll.
        self._poll_once()

    # ---- Menu callbacks ----
    def open_dashboard(self, _):
        if not _backend_alive():
            self.status_item.title = "Backend down — restarting…"
            # Revive the backend in a background thread so the main AppKit
            # thread isn't blocked by the sleep loop (which would freeze the UI).
            threading.Thread(target=self._revive_and_open, daemon=True).start()
        else:
            webbrowser.open(DASHBOARD_URL)

    def _revive_and_open(self):
        if _kickstart_backend():
            for _ in range(10):  # wait up to ~5s for it to come up
                time.sleep(0.5)
                if _backend_alive():
                    break
        webbrowser.open(DASHBOARD_URL)

    def refresh_now(self, _):
        self._poll_once()

    def restart_backend(self, _):
        self.status_item.title = "Restarting backend…"
        ok = _kickstart_backend()
        if not ok:
            self.status_item.title = "Restart failed — is the LaunchAgent installed?"
            return
        time.sleep(2)
        self._poll_once()

    # ---- Timer ----
    def _tick(self, _timer):
        self._poll_once()

    def _poll_once(self):
        # 45s timeout: the very first /api/summary call has to warm up the
        # `softwareupdate -l` cache, which can take 25+ seconds. Subsequent
        # polls return in under a second.
        try:
            with httpx.Client(timeout=45.0) as client:
                r = client.get(SUMMARY_URL)
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            self.title = DOT["offline"]
            self.status_item.title = f"Offline · {type(e).__name__}"
            # Self-heal: ask launchd to restart the backend (rate-limited).
            now = time.time()
            if now - self._last_restart_attempt > RESTART_COOLDOWN_SEC:
                self._last_restart_attempt = now
                if _kickstart_backend():
                    self.status_item.title = "Offline · restarting backend…"
            return

        overall = data.get("overall_severity", "ok")
        panels = data.get("panels", {})

        self.title = DOT.get(overall, DOT["offline"])
        ok_count = sum(1 for p in panels.values() if p.get("severity") == "ok")
        warn = sum(1 for p in panels.values() if p.get("severity") == "warn")
        crit = sum(1 for p in panels.values() if p.get("severity") == "critical")

        self.status_item.title = {
            "ok": f"All clear · {ok_count}/{len(panels)} healthy",
            "warn": f"{warn} warning(s) · review when free",
            "critical": f"{crit} critical · needs attention now",
        }.get(overall, "Status unknown")

        for key, mi in self.panel_items.items():
            p = panels.get(key, {})
            sev = p.get("severity", "ok")
            msg = (p.get("message") or "")[:48]
            mi.title = f"{DOT.get(sev, '⚪')}  {PANEL_LABELS[key]}  —  {msg}"

        self._handle_escalations(panels)

    def _handle_escalations(self, panels: dict):
        new_state = {}
        for key, p in panels.items():
            sev = p.get("severity", "ok")
            new_state[key] = sev
            prev = self.last_state.get(key, "ok")
            if (prev, sev) in {("ok", "warn"), ("ok", "critical"), ("warn", "critical")}:
                _notify(
                    title="DayGuard",
                    subtitle=PANEL_LABELS.get(key, key),
                    message=(p.get("message") or "needs attention")[:160],
                )
        self.last_state = new_state
        _save_state(new_state)


if __name__ == "__main__":
    DayGuardMenu().run()
