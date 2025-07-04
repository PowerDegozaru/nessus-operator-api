from __future__ import annotations

import datetime as dt
import logging
from http.cookies import SimpleCookie

from shortuuid import uuid

import conf

logger = logging.getLogger(__name__)


def nessus_auth_header(headers) -> dict[str, str]:
    """
    Resolve Nessus authentication for an incoming request.

    * If caller supplied `X-ApiKeys` or `X-Cookie`, forward it.
    * Otherwise fall back to configured API keys.
    """
    headers_lc = {k.lower(): v for k, v in dict(headers).items()}

    if "x-apikeys" in headers_lc:  # API keys header
        cookie_val = headers_lc["x-apikeys"]
        sc = SimpleCookie()
        sc.load(cookie_val)
        if "accessKey" not in sc or "secretKey" not in sc:
            logger.error("Malformed X-ApiKeys header")
            raise ValueError("X-ApiKeys header malformed")
        return {"X-ApiKeys": cookie_val}

    if "x-cookie" in headers_lc:  # Nessus session-cookie header
        cookie_val = headers_lc["x-cookie"]
        sc = SimpleCookie()
        sc.load(cookie_val)
        if "token" in sc:
            return {"X-Cookie": cookie_val}

    logger.debug("Falling back to config-provided API keys")
    return conf.NESSUS_AUTH_HEADER


def build_scan_name(prefix: str = "") -> str:
    """Timestamp + short-uuid for guaranteed uniqueness (safe for Nessus UI)."""
    now = dt.datetime.now().astimezone()
    return f"{prefix}{now:%y%m%d-%H%M%S}-{uuid()}"
