"""This module acts as purely backend logic, functions here are called directly, not as HTTP requests.
It is typical for the functions here to call browser-use or the official Nessus API directly"""

import time
import requests
from fastapi import HTTPException, Response

import conf
from models import (
    ExportFormat,
    Folder,
    ListScansItem,
)

def list_folders(auth_headers) -> list[Folder]:
    r = requests.get(conf.NESSUS_URL + "/folders", headers=auth_headers, verify=conf.SSL_VERIFY)
    r_json = r.json()

    raw_folders = r_json["folders"]
    return [Folder.model_validate(raw_folder) for raw_folder in raw_folders]


def create_folder(name: str, auth_headers) -> Response:
    r = requests.post(conf.NESSUS_URL + "/folders", json={"name": name}, headers=auth_headers, verify=conf.SSL_VERIFY)
    return Response(
        status_code=r.status_code,
        headers=r.headers,
        content=r.content,
    )


def get_folder_id(name: str, auth_headers, *, create_if_not_exists: bool = False) -> int:
    """Returns the folder IDs of the folder with the given name (case insensitive), 404 if not found"""
    def get_folder_id_helper() -> int | None:
        folders = list_folders(auth_headers)
        name_lowered = name.lower()
        filtered = [folder.id for folder in folders if folder.name.lower() == name_lowered]
        assert len(filtered) <= 1, "There are folders with duplicated names!"

        if filtered:
            return filtered[0]
        else:
            return None

    folder_id = get_folder_id_helper()
    if folder_id is not None:
        return folder_id

    if not create_if_not_exists:
        raise HTTPException(status_code=404, detail="Folder not found")

    # Else we create and then return the folder ID
    r = create_folder(name, auth_headers)
    if r.status_code != 200:
        raise HTTPException(
            status_code=r.status_code,
            detail=r.body,
            headers=dict(r.headers)
        )

    folder_id = get_folder_id_helper()
    if folder_id is None:
        raise HTTPException(status_code=404, detail="Folder not found (even after attempted creation)")
    return folder_id

def get_folder(folder_id: int, auth_headers) -> Folder:
    """Returns the Folder by ID, 404 if not found"""
    folders = list_folders(auth_headers)
    filtered = [folder for folder in folders if folder.id == folder_id]
    assert len(filtered) <= 1, "There are folders with duplicated IDs! (not supposed to be possible)"

    if filtered:
        return filtered[0]
    else:
        raise HTTPException(status_code=404, detail="Folder not found")

def list_scans(auth_headers, folder_id: int | None = None) -> list[ListScansItem]:
    params = {}
    if folder_id is not None:
        params["folder_id"] = folder_id
    r = requests.get(conf.NESSUS_URL + "/scans", params=params, headers=auth_headers, verify=conf.SSL_VERIFY)
    r_json = r.json()

    if r.status_code != 200 :raise HTTPException(r.status_code, r.text)
    raw_scans = r_json.get("scans") or []   # tolerate “null”
    res = []
    for raw_scan in raw_scans:
        res.append(ListScansItem(
            name=raw_scan["name"],
            scan_type=raw_scan["scan_type"],
            id=raw_scan["id"],
            folder_id=folder_id if folder_id is not None else raw_scan["folder_id"],
            status=raw_scan["status"],
            uuid=raw_scan["uuid"],
            creation_date=raw_scan["creation_date"],
            )
        )
    return res


def get_scan_id(name: str, *, folder_id: int|None = None, auth_headers) -> list[int]:
    """Get Scan ID of scans with the exact same name (optionally in the given folder)"""
    scans = list_scans(folder_id=folder_id, auth_headers=auth_headers)
    filtered_scans = [scan.id for scan in scans if scan.name == name]
    return filtered_scans


def get_scan_report_url(auth_headers, scan_id: int, format: ExportFormat, max_polls = 10, poll_interval_s = 1) -> str:
    REPORT_TEMPLATE_ID = 167   #TODO: This is the "Detailed Vulnerabilities By Host" Template, the value was reverse engineered
                               #      from the "Generate Report" feature of the website, need to find a better way to list the
                               #      various template IDs and choose from
    r = requests.post(conf.NESSUS_URL + f"/scans/{scan_id}/export", json={"format": format, "template_id": REPORT_TEMPLATE_ID}, headers=auth_headers, verify=conf.SSL_VERIFY)
    r.raise_for_status()

    token = r.json()["token"]

    for _ in range(max_polls):
        r = requests.get(conf.NESSUS_URL + f"/tokens/{token}/status", headers=auth_headers, verify=conf.SSL_VERIFY)
        r.raise_for_status()
        if r.json()["status"] == "ready":
            return conf.NESSUS_URL + f"/tokens/{token}/download"
        time.sleep(poll_interval_s)

    raise Exception(f"Download not ready after polling for {max_polls} (max_polls) with interval {poll_interval_s}s")

