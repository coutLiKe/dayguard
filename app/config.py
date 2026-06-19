"""Config loader. Reads config.json if present, else falls back to defaults."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"
EXAMPLE_PATH = ROOT / "config.example.json"

DEFAULTS = {
    "domains": [],
    "known_devices": [],
    "home_gateway_macs": [],
    "cve_keywords": ["python", "macos", "openssl"],
    "cve_min_cvss": 7.0,
    "ollama_url": "http://localhost:11434",
    "ollama_model": "llama3.2:3b",
}


def load_config() -> dict:
    path = CONFIG_PATH if CONFIG_PATH.exists() else EXAMPLE_PATH
    if not path.exists():
        return DEFAULTS
    with open(path) as f:
        cfg = json.load(f)
    return {**DEFAULTS, **cfg}


CONFIG = load_config()
