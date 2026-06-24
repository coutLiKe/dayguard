# DayGuard

Personal security dashboard for macOS. Lives in your menu bar, opens to a full dashboard at `http://localhost:8765`. **100% free — no paid APIs, no subscriptions, no telemetry.**

**Morning Brief** at the top of the dashboard uses a local LLM (Ollama, free, runs offline) to summarize all signals into a 2-3 sentence narrative — like a thoughtful colleague's text in the morning.

Seven panels at a glance:

**This Mac**
- **macOS Security Posture** — FileVault, firewall, Gatekeeper, SIP, software updates, failed auth attempts, Time Machine
- **Home Network** — scans your LAN via `arp`, flags devices you don't recognize
- **VPN & Tunnels** — `scutil --nc list` + filtered `utun` interfaces
- **Disk Space** — main volume free %, warns under 15%, critical under 5%
- **Recent App Changes** — `/Applications` modified in the last 7 days, flags unsigned bundles

**Out in the World**
- **Domain & SSL Health** — pings your sites, flags certs expiring soon, slow responses
- **Recent CVEs** — filters last 48h of NVD, exact-keyword match + CVSS ≥ 7.0 floor

## Architecture

Two processes, both started at login by `launchd`:

1. **Backend** — FastAPI server on `localhost:8765` runs the checks and serves the dashboard
2. **Menu bar app** — Polls the backend every 5 min, shows a colored dot (green/yellow/red) in your menu bar, fires macOS notifications on severity escalations

## Setup

```bash
cd dayguard
./dayguardctl install   # creates the venv, installs deps, starts everything

# Customize what's monitored
cp config.example.json config.json
# edit config.json — add your domains, your devices, CVE keywords

# Install Ollama for the Morning Brief (free, local)
brew install ollama
ollama pull llama3.2:3b   # ~2 GB, one-time download
ollama serve              # leave running in a tab, or set up a launchd plist

# (Optional) run manually instead of via launchd:
"$HOME/Library/Application Support/DayGuard/venv/bin/python3" -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

> **Keep the project out of iCloud Drive.** Do **not** put DayGuard in
> `~/Documents` or `~/Desktop` — iCloud syncs those folders and "optimizes"
> (evicts) file contents to the cloud. At login, `launchd` then starts the
> backend before iCloud has re-downloaded the code, and Python crashes on
> import with `OSError: [Errno 11] Resource deadlock avoided` — so the app
> silently fails to start after every restart. Keep the repo somewhere iCloud
> never touches, e.g. `~/dayguard`. The venv lives outside the project at
> `~/Library/Application Support/DayGuard/venv` for the same reason — never
> move it back into the project folder.

Open http://localhost:8765 to see the dashboard.

**Pro tip:** in Safari, with the dashboard open, go to **File → Add to Dock** to get a real Dock icon for DayGuard with no browser chrome.

## Notes on each panel

**macOS posture** uses `fdesetup`, `socketfilterfw`, `spctl`, `csrutil`, `softwareupdate`, `log show`, `tmutil`. All read-only. `softwareupdate -l` is slow (10–30s) so it's cached for 24h in `.macos_cache.json`. Some commands prompt the first time you grant Terminal full-disk access in System Settings.

**Network** uses `arp -a` (no root needed). For a richer scan, swap to `nmap -sn 192.168.1.0/24` later — also free.

**VPN** is informational — severity is always OK because VPN is your choice, not a security failure. Filters Apple's iCloud Private Relay tunnels out of `utun` detection.

**Recent App Changes** is named that way because Sparkle-based auto-updaters touch `mtime` when they update — so this shows "changes," not just fresh installs. That's actually useful security signal (you'll notice if an app changes unexpectedly).

**CVEs** hits NVD's public REST API (no key, free). Filter: exact-word keyword match AND CVSS ≥ 7.0. Tune `cve_keywords` and `cve_min_cvss` in config.

**Morning Brief** uses Ollama (free). Default model is `llama3.2:3b` (~2 GB, ~1 sec per brief on M-series). For a smarter brief, try `qwen2.5:7b`; for a tighter one, `gemma3:1b`. If Ollama isn't running, the brief falls back to a deterministic rule-based summary so the dashboard never breaks.

## Auto-start at login (dayguardctl)

One script manages everything:

```bash
chmod +x dayguardctl      # first time only
./dayguardctl install     # install LaunchAgents, kill stray servers, start both
./dayguardctl status      # are the services up? does the API answer?
./dayguardctl restart     # bounce backend + menubar
./dayguardctl logs        # tail recent logs
./dayguardctl doctor      # full diagnosis when something's wrong
./dayguardctl stop        # unload both services
```

Logs land in `logs/` inside the project. The menu bar app also self-heals: if it
finds the backend down, it asks launchd to restart it (and "Open Dashboard"
revives the backend before opening the browser).

## Home vs. away networks

The Home Network panel only flags unknown devices when you're actually at home.
Set your router's MAC in `config.json`:

```json
"home_gateway_macs": ["aa:bb:cc:dd:ee:01"]
```

Find it (while at home): `route -n get default` for the gateway IP, then
`arp -a | grep <that ip>` for its MAC. On any other network the panel reports
device count informationally and stays green. Leave the list empty to keep the
old always-flag behavior.

## Cost: $0

- All system commands are built into macOS
- NVD API: free, no key
- Ollama + open-weight models: free
- Python libraries: free / open source
- No cloud sync, no telemetry, no subscriptions

## Roadmap

- **v4** — clipboard secret watcher (background process, low-FP patterns only), VirusTotal hash lookup for recent app changes (free tier), weekly PDF report
- **v5** — native Swift `.app` wrapper, mobile read-only view

## Why this project

Combines the security focus from PhishGuard / PassGuard with the IT / networking track from NPower NetSYA. Runs daily, locally, privacy-first — same philosophy as the other tools.
