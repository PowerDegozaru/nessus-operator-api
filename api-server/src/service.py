from __future__ import annotations

import logging
import time
from typing import Any

import requests
from fastapi import HTTPException, Response

import conf
from models import ExportFormat, Folder, ListScansItem

logger = logging.getLogger(__name__)


def _safe_request(method: str, url: str, **kwargs: Any) -> requests.Response:
    """Wrap `requests` with consistent error handling & logging."""
    try:
        r = requests.request(method, url, verify=conf.SSL_VERIFY, **kwargs)
        r.raise_for_status()
        return r
    except requests.exceptions.RequestException as exc:
        logger.exception("Upstream Nessus call failed: %s %s", method, url)
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ——————————————————— folders ———————————————————
def list_folders(auth_headers) -> list[Folder]:
    r = _safe_request("GET", conf.NESSUS_URL + "/folders", headers=auth_headers)
    raw_folders = r.json().get("folders", [])
    return [Folder.model_validate(f) for f in raw_folders]


def create_folder(name: str, auth_headers) -> Response:
    r = _safe_request(
        "POST",
        conf.NESSUS_URL + "/folders",
        json={"name": name},
        headers=auth_headers,
    )
    return Response(
        status_code=r.status_code,
        headers=r.headers,
        content=r.content,
    )


def get_folder_id(name: str, auth_headers, *, create_if_not_exists: bool = False) -> int:
    """Return the *id* of the folder named *name* (case-insensitive)."""
    def _search() -> int | None:
        folders = list_folders(auth_headers)
        matches = [f.id for f in folders if f.name.lower() == name.lower()]
        if len(matches) > 1:
            logger.error("Duplicate folder names detected: %s", name)
            raise HTTPException(
                status_code=500, detail="Duplicate folder names detected"
            )
        return matches[0] if matches else None

    folder_id = _search()
    if folder_id is not None:
        return folder_id
    if not create_if_not_exists:
        raise HTTPException(status_code=404, detail="Folder not found")

    logger.info("Folder '%s' not found; creating.", name)
    create_resp = create_folder(name, auth_headers)
    if create_resp.status_code != 200:
        raise HTTPException(
            status_code=create_resp.status_code,
            detail=create_resp.content.decode(),
            headers=dict(create_resp.headers),
        )

    folder_id = _search()
    if folder_id is None:
        raise HTTPException(
            status_code=500, detail="Folder creation acknowledged but not found"
        )
    return folder_id


def get_folder(folder_id: int, auth_headers) -> Folder:
    folders = list_folders(auth_headers)
    matches = [f for f in folders if f.id == folder_id]
    if not matches:
        raise HTTPException(status_code=404, detail="Folder not found")
    if len(matches) > 1:
        logger.error("Duplicate folder IDs detected: %s", folder_id)
        raise HTTPException(status_code=500, detail="Duplicate folder IDs detected")
    return matches[0]


# ——————————————————— scans ———————————————————
def list_scans(auth_headers, folder_id: int | None = None) -> list[ListScansItem]:
    params = {"folder_id": folder_id} if folder_id is not None else {}
    r = _safe_request(
        "GET",
        conf.NESSUS_URL + "/scans",
        params=params,
        headers=auth_headers,
    )
    raw_scans = r.json().get("scans") or []
    return [
        ListScansItem(
            name=s["name"],
            scan_type=s["scan_type"],
            id=s["id"],
            folder_id=folder_id if folder_id is not None else s["folder_id"],
            status=s["status"],
            uuid=s.get("uuid"),
            creation_date=s["creation_date"],
        )
        for s in raw_scans
    ]


def get_scan_id(name: str, *, folder_id: int | None = None, auth_headers) -> list[int]:
    scans = list_scans(folder_id=folder_id, auth_headers=auth_headers)
    return [s.id for s in scans if s.name == name]


# ——————————————————— reports ———————————————————
def get_scan_report_url(
    auth_headers,
    scan_id: int,
    format: ExportFormat,
    *,
    max_polls: int = 10,
    poll_interval_s: int = 1,
) -> str:
    REPORT_TEMPLATE_ID = 167  # TODO: discover dynamically

    r = _safe_request(
        "POST",
        conf.NESSUS_URL + f"/scans/{scan_id}/export",
        json={"format": format, "template_id": REPORT_TEMPLATE_ID},
        headers=auth_headers,
    )
    token = r.json().get("token")
    if not token:
        raise HTTPException(status_code=500, detail="Export token missing from response")

    logger.info("Polling export token %s", token)
    for _ in range(max_polls):
        status_resp = _safe_request(
            "GET",
            conf.NESSUS_URL + f"/tokens/{token}/status",
            headers=auth_headers,
        )
        if status_resp.json().get("status") == "ready":
            return conf.NESSUS_URL + f"/tokens/{token}/download"
        time.sleep(poll_interval_s)

    raise HTTPException(
        status_code=504,
        detail=f"Export not ready after {max_polls * poll_interval_s}s of polling",
    )
