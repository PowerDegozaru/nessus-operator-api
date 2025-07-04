from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Request, Response

import browser_tasks
import conf
import service
import utils
from models import (
    CreateFolderRequest,
    ExportFormat,
    Folder,
    GetSessionTokenRequest,
    ListScansItem,
    ScanResult,
    ScanResultHost,
    ScanStatus,
    ScanTemplate,
    StartScanRequest,
    StartScanResponse,
    Vulnerability,
)

# ——————————————————— logging ———————————————————
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Windows event-loop tweak (kept from original code)
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.set_event_loop(asyncio.new_event_loop())

app = FastAPI()


# ——————————————————— helper ———————————————————
def _proxy_request(
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """Wrapper that adds robust error handling to outbound requests."""
    try:
        r = requests.request(method, url, verify=conf.SSL_VERIFY, **kwargs)
        r.raise_for_status()
        return r
    except requests.exceptions.RequestException as exc:
        logger.exception("Upstream request failure: %s %s", method, url)
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ——————————————————— endpoints ———————————————————
@app.post("/session")
def get_session_token(body: GetSessionTokenRequest) -> str:
    r = _proxy_request(
        "POST",
        conf.NESSUS_URL + "/session",
        json={"username": body.username, "password": body.password},
    )
    return r.json().get("token", "")  # empty string if key missing


@app.get("/folders")
def list_folders(req: Request) -> list[Folder]:
    return service.list_folders(auth_headers=utils.nessus_auth_header(req.headers))


@app.get("/folders/getid")
def get_folder_id(
    req: Request, name: str, create_if_not_exists: bool = False
) -> int:
    return service.get_folder_id(
        name=name,
        create_if_not_exists=create_if_not_exists,
        auth_headers=utils.nessus_auth_header(req.headers),
    )


@app.post("/folders")
def create_folder(req: Request, body: CreateFolderRequest) -> Response:
    return service.create_folder(
        name=body.name, auth_headers=utils.nessus_auth_header(req.headers)
    )


@app.post("/start_scan")
async def start_scan(body: StartScanRequest, req: Request) -> StartScanResponse:
    folder_name = "nessus-controller"
    folder_id = service.get_folder_id(
        name=folder_name,
        create_if_not_exists=True,
        auth_headers=utils.nessus_auth_header(req.headers),
    )
    folder = service.get_folder(
        folder_id=folder_id, auth_headers=utils.nessus_auth_header(req.headers)
    )
    unique_scan_name = utils.build_scan_name(body.scan_name_prefix)

    try:
        log = await browser_tasks.scan_operator_run(
            body.target, body.scan_type, unique_scan_name, folder
        )
        logger.debug("Operator log: %s", log)
    except Exception as exc:
        logger.exception("Operator run failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    scan_ids = service.get_scan_id(
        name=unique_scan_name,
        folder_id=folder_id,
        auth_headers=utils.nessus_auth_header(req.headers),
    )

    if len(scan_ids) != 1:
        msg = (
            "Internal Error: scan ID not unique"
            if len(scan_ids) > 1
            else "Internal Error: scan ID not found"
        )
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)
    return StartScanResponse(ok=True, scan_id=scan_ids[0], scan_name=unique_scan_name)


@app.get("/list_scan_templates")
def list_scan_templates(req: Request) -> list[ScanTemplate]:
    r = _proxy_request(
        "GET",
        conf.NESSUS_URL + "/editor/scan/templates",
        headers=utils.nessus_auth_header(req.headers),
    )
    templates = r.json().get("templates", [])
    return [
        ScanTemplate(
            title=t["title"],
            uuid=t["uuid"],
            desc=t.get("desc", ""),
        )
        for t in templates
    ]


@app.get("/list_scans")
def list_scans(req: Request, folder_id: int | None = None) -> list[ListScansItem]:
    return service.list_scans(
        auth_headers=utils.nessus_auth_header(req.headers), folder_id=folder_id
    )


@app.get("/scan_status")
def get_scan_status(req: Request, scan_id: int) -> ScanStatus:
    r = _proxy_request(
        "GET",
        conf.NESSUS_URL + f"/scans/{scan_id}",
        headers=utils.nessus_auth_header(req.headers),
    )
    info = r.json().get("info", {})
    return ScanStatus(
        name=info.get("name", ""),
        status=info.get("status", ""),
        targets=info.get("targets", ""),
        policy=info.get("policy", ""),
        policy_template_uuid=info.get("policy_template_uuid", ""),
        folder_id=info.get("folder_id", 0),
        timestamp=info.get("timestamp", 0),
    )


@app.get("/scan_results")
def get_scan_results(req: Request, scan_id: int) -> ScanResult:
    r = _proxy_request(
        "GET",
        conf.NESSUS_URL + f"/scans/{scan_id}",
        headers=utils.nessus_auth_header(req.headers),
    )
    data = r.json()
    vulns = [
        Vulnerability(
            count=v["count"],
            plugin_name=v["plugin_name"],
            severity=v["severity"],
            plugin_family=v["plugin_family"],
        )
        for v in data.get("vulnerabilities", [])
    ]
    hosts = [
        ScanResultHost(
            totalchecksconsidered=h["totalchecksconsidered"],
            numchecksconsidered=h["numchecksconsidered"],
            host_id=h["host_id"],
            hostname=h["hostname"],
            score=h["score"],
            critical=h["critical"],
            high=h["high"],
            medium=h["medium"],
            low=h["low"],
            info=h["info"],
        )
        for h in data.get("hosts", [])
    ]
    return ScanResult(hosts=hosts, vulnerabilities=vulns)


@app.get("/scan_report")
def get_scan_report_url(
    req: Request, scan_id: int, format: ExportFormat = ExportFormat.pdf
) -> str:
    return service.get_scan_report_url(
        scan_id=scan_id,
        format=format,
        auth_headers=utils.nessus_auth_header(req.headers),
    )
