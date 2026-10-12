"""Configuration management for BHARYDANGEROUS-Investigator."""
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from bharydangerous.core.constants import (
    DEFAULT_GEMINI_MODEL,
    DEFAULT_LOCAL_AI_URL,
)

CONFIG_DIR = Path.home() / ".bharydangerous"
CONFIG_FILE = CONFIG_DIR / "config.json"

def get_config_dir() -> Path:
    """Return the configuration directory and ensure it exists with secure permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR

def load_user_config() -> Dict[str, Any]:
    """Load configuration from ~/.bharydangerous/config.json if present."""
    if CONFIG_FILE.is_file():
        try:
            with CONFIG_FILE.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_user_config(config_data: Dict[str, Any]) -> None:
    """Save configuration to ~/.bharydangerous/config.json with restricted permissions."""
    get_config_dir()
    with CONFIG_FILE.open("w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)
    # Set 0600 on POSIX platforms
    try:
        if os.name != "nt":
            CONFIG_FILE.chmod(0o600)
    except Exception:
        pass

def get_gemini_api_key() -> Optional[str]:
    """Retrieve Gemini API key from environment variable or stored configuration."""
    env_key = os.environ.get("GEMINI_API_KEY")
    if env_key:
        return env_key.strip()
    user_cfg = load_user_config()
    return user_cfg.get("gemini_api_key")

def get_gemini_model() -> str:
    """Retrieve preferred Gemini model name."""
    return os.environ.get("GEMINI_MODEL") or load_user_config().get("gemini_model") or DEFAULT_GEMINI_MODEL

def get_local_ai_url() -> str:
    """Retrieve local AI / Ollama URL."""
    return os.environ.get("LOCAL_AI_URL") or load_user_config().get("local_ai_url") or DEFAULT_LOCAL_AI_URL
