"""
THIS FILE IS NOT MEANT TO BE MODIFIED DIRECTLY FOR CONFIGURATION.
All configuration should be done through the config.toml file.
All values exposed here should be **READ-ONLY**.
"""

from __future__ import annotations

import logging
from pathlib import Path
import tomllib

logger = logging.getLogger(__name__)


def _project_root(marker_file: str = "config.toml") -> Path:
    """Walk parents until we find *marker_file*; raises if not found."""
    cur_path = Path(__file__).resolve()
    for path in cur_path.parents:
        if (path / marker_file).exists():
            return path
    raise RuntimeError(f"Project root (containing {marker_file}) not found.")


PROJECT_ROOT = _project_root()
CONFIG_PATH = PROJECT_ROOT / "config.toml"

try:
    with open(CONFIG_PATH, "rb") as fp:
        _conf = tomllib.load(fp)
except FileNotFoundError as e:
    logger.critical("Configuration file missing: %s", CONFIG_PATH)
    raise
except tomllib.TOMLDecodeError as e:
    logger.critical("Malformed TOML in %s: %s", CONFIG_PATH, e)
    raise

# ——————————————————— Nessus ———————————————————
NESSUS_URL: str = _conf["nessus"]["url"]
NESSUS_USERNAME: str = _conf["nessus"]["username"]
NESSUS_PASSWORD: str = _conf["nessus"]["password"]

NESSUS_ACCESS_KEY: str = _conf["nessus"]["access_key"]
NESSUS_SECRET_KEY: str = _conf["nessus"]["secret_key"]
NESSUS_AUTH_HEADER: dict[str, str] = {
    "X-ApiKeys": f"accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY};"
}

# ——————————————————— LLM ———————————————————
GOOGLE_API_KEY: str = _conf["llm"]["google_api_key"]
LLM_MODEL: str = _conf["llm"]["model"]

# ——————————————————— Dev ———————————————————
SSL_VERIFY: bool = _conf["dev"]["ssl_verify"]
IS_HEADLESS: bool = _conf["dev"]["headless_operator"]
