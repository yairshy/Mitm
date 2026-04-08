"""Configuration management for MITM TV Sync."""

from pathlib import Path
from typing import Optional

import yaml


DEFAULT_CONFIG_DIR = Path(__file__).parent.parent / "config"
USER_CONFIG_DIR = Path.home() / ".mitm_tv_sync"


def load_rules(custom_rules_path: Optional[str] = None) -> dict:
    """Load rewrite rules from YAML config.

    Priority: custom path > user config > default config.
    """
    if custom_rules_path:
        path = Path(custom_rules_path)
        if not path.exists():
            raise FileNotFoundError(f"Rules file not found: {path}")
        with open(path) as f:
            return yaml.safe_load(f) or {}

    # Try user config
    user_rules = USER_CONFIG_DIR / "rules.yaml"
    if user_rules.exists():
        with open(user_rules) as f:
            return yaml.safe_load(f) or {}

    # Fall back to default
    default_rules = DEFAULT_CONFIG_DIR / "default_rules.yaml"
    if default_rules.exists():
        with open(default_rules) as f:
            return yaml.safe_load(f) or {}

    return _minimal_rules()


def save_rules(rules: dict, path: Optional[str] = None) -> Path:
    """Save rules to a YAML file."""
    if path:
        out = Path(path)
    else:
        USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        out = USER_CONFIG_DIR / "rules.yaml"

    with open(out, "w") as f:
        yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
    return out


def _minimal_rules() -> dict:
    """Return a minimal set of rules when no config file exists."""
    return {
        "headers": [
            {"name": "User-Agent", "enabled": True},
            {"name": "X-Device-Id", "enabled": True},
            {"name": "X-Device-ID", "enabled": True},
            {"name": "X-Client-Id", "enabled": True},
        ],
        "body_fields": [
            {"name": "deviceId", "enabled": True},
            {"name": "device_id", "enabled": True},
            {"name": "serialNumber", "enabled": True},
            {"name": "macAddress", "enabled": True},
        ],
        "query_params": [
            {"name": "device_id", "enabled": True},
            {"name": "deviceId", "enabled": True},
        ],
        "target_domains": [],
        "ignore_domains": [
            "google.com",
            "googleapis.com",
            "gstatic.com",
            "facebook.com",
        ],
    }


def get_data_dir() -> Path:
    """Get the data directory for storing fingerprints and logs."""
    data_dir = USER_CONFIG_DIR
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir
