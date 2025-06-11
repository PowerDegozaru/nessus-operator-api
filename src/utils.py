from pathlib import Path
import tomllib
import datetime as dt
from shortuuid import uuid
from http.cookies import SimpleCookie

CONFIG_PATH = (Path(__file__).parent.parent / "config.toml").resolve()
with open(CONFIG_PATH, "rb") as f:
    conf = tomllib.load(f)

NESSUS_ACCESS_KEY = conf["nessus"]["access_key"]
NESSUS_SECRET_KEY = conf["nessus"]["secret_key"]

NESSUS_AUTH_HEADER = {"X-ApiKeys": f"accessKey={NESSUS_ACCESS_KEY}; secretKey={NESSUS_SECRET_KEY};"}

def nessus_auth_header(headers) -> dict:
    """Extracts Nessus authentication headers if present,
    else fallback to the default API keys provided in the config file"""
    headers = dict(headers)
    keys_lowered = [key.lower() for key in headers]

    if "x-apikeys" in keys_lowered:
        x_apikeys = SimpleCookie()
        x_apikeys.load(headers["x-apikeys"])
        if "accessKey" not in x_apikeys or "secretKey" not in x_apikeys:
            raise Exception("X-ApiKeys Header Malformed (missing accessKey or secretKey)")
        return {"X-ApiKeys": headers["x-apikeys"]}

    if "x-cookie" in keys_lowered:
        x_cookie = SimpleCookie()
        x_cookie.load(headers["x-cookie"])
        if "token" in x_cookie:
            return {"X-Cookie": headers["x-cookie"]}

    return NESSUS_AUTH_HEADER

def build_scan_name(prefix="") -> str:
    now = dt.datetime.now().astimezone()
    unique_suffix = "-" + uuid()
    return f"{prefix}{now:%y%m%d-%H%M%S{unique_suffix}}"

