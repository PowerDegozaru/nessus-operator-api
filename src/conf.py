"""THIS FILE IS NOT MEANT TO BE MODIFIED DIRECTLY FOR CONFIGURATION
All configuration should be done through the `config.toml` file
All values exposed here should be READ-ONLY"""

from pathlib import Path
import tomllib

# Project Root Directory
def _project_root(file_in_root = "config.toml") -> Path:
    cur_path = Path(__file__)
    for path in cur_path.parents:
        if (path/file_in_root).exists():
            return path
    raise Exception(f"Project Root with file `{file_in_root}` doesn't exist.")


PROJECT_ROOT = _project_root()
CONFIG_PATH = PROJECT_ROOT/"config.toml"

with open(CONFIG_PATH, "rb") as f:
    conf = tomllib.load(f)

# Nessus
NESSUS_URL = conf["nessus"]["url"]  # Actual Nessus API URL
NESSUS_USERNAME = conf["nessus"]["username"]
NESSUS_PASSWORD = conf["nessus"]["password"]

NESSUS_ACCESS_KEY = conf["nessus"]["access_key"]
NESSUS_SECRET_KEY = conf["nessus"]["secret_key"]
NESSUS_AUTH_HEADER = {"X-ApiKeys": f"accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY};"}

# LLM
GOOGLE_API_KEY = conf["llm"]["google_api_key"]
LLM_MODEL = conf["llm"]["model"]

# Development
SSL_VERIFY = conf["dev"]["ssl_verify"]
IS_HEADLESS = conf["dev"]["headless_operator"]

