"""
config_loader.py - Load và merge config từ config.yaml + CLI overrides.
"""
import yaml
from pathlib import Path


_DEFAULT_CONFIG = {
    "scanner": {
        "max_depth": 3, "max_pages": 50, "timeout": 10,
        "concurrency": 8, "rate_limit": 8.0, "burst": 15,
        "user_agent": "WebVulnScanner/2.0",
        "verify_ssl": False, "follow_redirects": True,
    },
    "modules": {
        "sqli": True, "xss": True, "sensitive_files": True,
        "open_redirect": True, "headers": True,
        "waf_detect": True, "blind_sqli": True,
    },
    "detection": {
        "use_response_differ": True,
        "use_payload_mutator": True,
        "confidence_threshold": 0.65,
        "differ_threshold": 0.93,
    },
    "reporting": {
        "cvss_scoring": True,
        "include_waf_info": True,
        "output_dir": ".",
    },
    "logging": {"level": "INFO", "log_file": None},
}


def load_config(path: str | None = None) -> dict:
    """Load config.yaml nếu tồn tại, merge với defaults."""
    config = _deep_copy(_DEFAULT_CONFIG)

    config_path = Path(path) if path else Path("config.yaml")
    if config_path.exists():
        with open(config_path, encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
        config = _deep_merge(config, user_config)

    return config


def _deep_copy(d: dict) -> dict:
    import copy
    return copy.deepcopy(d)


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result