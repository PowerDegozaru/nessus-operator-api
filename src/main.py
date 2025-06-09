"""
Simple RESTful Nessus API that makes use of browser-use for any requests that cannot be forwarded to API calls in Nessus Essentials.

If there is a need to call the Nessus APIs, authentication headers will be forwarded (session token / API keys useful for authentication),
if none exists, defaults will be used from the config.toml file.

The functions here should be purely API Endpoints, service logic should be in service.py
"""

from fastapi import FastAPI, Request, Response, HTTPException
from pathlib import Path
import tomllib
import requests
import logging
import sys
import asyncio

import browser_tasks
import utils
import service
from models import (
    GetSessionTokenRequest,
    Folder,
    CreateFolderRequest,
    StartScanRequest,
    StartScanResponse,
    ScanTemplate,
    ListScansItem,
    ScanStatus,
    Vulnerability,
    ScanResultHost,
    ScanResult,
)

app = FastAPI()

CONFIG_PATH = (Path(__file__).parent.parent / "config.toml").resolve()
with open(CONFIG_PATH, "rb") as f:
    conf = tomllib.load(f)

NESSUS_URL = conf["nessus"]["url"]  # Actual Nessus API URL

DEV_MODE = conf["app"]["is_dev_mode"]
SSL_VERIFY = not DEV_MODE

# Logging
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.set_event_loop(asyncio.new_event_loop())

logging.basicConfig(level=logging.INFO)
logging.info("Loop policy is %s, loop class is %s",
             asyncio.get_event_loop_policy().__class__.__name__,
             type(asyncio.get_event_loop()).__name__)      # should say ProactorEventLoop


@app.post("/session")
def get_session_token(body:GetSessionTokenRequest) -> str:
    """Get session token for authentication to call the other API calls"""
    data = {"username": body.username, "password": body.password}
    r = requests.post(NESSUS_URL + "/session", json=data, verify=SSL_VERIFY)
    if r.status_code != 200:
        return r.json()
    return r.json()["token"]


@app.get("/folders")
def list_folders(req: Request) -> list[Folder]:
    return service.list_folders(auth_headers=utils.nessus_auth_header(req.headers))


@app.get("/folders/getid")
def get_folder_id(req: Request, name: str, create_if_not_exists: bool = False) -> int:
    """API Endpoint: Returns the folder IDs of the folder with the given name (case insensitive), 404 if not found """
    return service.get_folder_id(name=name,
                                 create_if_not_exists=create_if_not_exists,
                                 auth_headers=utils.nessus_auth_header(req.headers))


@app.post("/folders")
def create_folder(req: Request, body: CreateFolderRequest) -> Response:
    return service.create_folder(name=body.name,
                                 auth_headers=utils.nessus_auth_header(req.headers))


@app.post("/start_scan")
#async def start_scan(body: StartScanRequest, req: Request) -> StartScanResponse:
async def start_scan(body: StartScanRequest, req: Request):
    folder_name = "nessus-controller"   # Custom folder to store scans creates by our Nessus Controller
    folder_id = service.get_folder_id(name=folder_name,         # Also creates if doesn't exists
                                      create_if_not_exists=True,
                                      auth_headers=utils.nessus_auth_header(req.headers))
    folder = service.get_folder(folder_id=folder_id, auth_headers=utils.nessus_auth_header(req.headers))
    unique_scan_name = utils.build_scan_name(body.scan_name_prefix)

    try:
        log = await browser_tasks.scan_operator_run(body.target, body.scan_type, unique_scan_name, folder)
    except Exception as e:
        logging.exception("Scan failed")
        raise HTTPException(status_code=500, detail=str(e))

    # Try to get Scan ID by listing all scans
    scan_ids = service.get_scan_id(name=unique_scan_name,
                                   folder_id=folder_id,
                                   auth_headers=utils.nessus_auth_header(req.headers))

    if len(scan_ids) > 1:
        msg = "Internal Error: Scan ID Not Unique!"
        logging.exception(msg)
        raise HTTPException(status_code=500, detail=msg)
    elif len(scan_ids) != 1:
        msg = "Internal Error: Scan ID Not Found, Scan was possibly not initiated properly by Operator"
        logging.exception(msg)
        raise HTTPException(status_code=500, detail= msg)

    scan_id = scan_ids[0]

    return StartScanResponse(ok=True, scan_id=scan_id, scan_name=unique_scan_name)


@app.get("/list_scan_templates")
def list_scan_templates(req: Request) -> list[ScanTemplate]:
    res = []

    r = requests.get(NESSUS_URL + "/editor/scan/templates", headers=utils.nessus_auth_header(req.headers), verify=SSL_VERIFY)
    r_json = r.json()

    raw_templates = r_json["templates"]
    for raw_template in raw_templates:
        res.append(ScanTemplate(
            title=raw_template["title"],
            uuid=raw_template["uuid"],
            desc=raw_template["desc"],
            )
        )
    return res


@app.get("/list_scans")
def list_scans(req: Request, folder_id: int | None = None) -> list[ListScansItem]:
    return service.list_scans(auth_headers=utils.nessus_auth_header(req.headers), folder_id=folder_id)


@app.get("/scan_status")
def get_scan_status(req: Request, scan_id: int) -> ScanStatus:
    r = requests.get(NESSUS_URL + f"/scans/{scan_id}", headers=utils.nessus_auth_header(req.headers), verify=SSL_VERIFY)
    r_json = r.json()

    info = r_json["info"]

    return ScanStatus(
        name=info["name"],
        status=info["status"],
        targets=info["targets"],
        policy=info["policy"],
        policy_template_uuid= info["policy_template_uuid"],
        folder_id=info["folder_id"],
        timestamp=info["timestamp"],
    )


@app.get("/scan_results")
def get_scan_results(req: Request, scan_id: int):
    r = requests.get(NESSUS_URL + f"/scans/{scan_id}", headers=utils.nessus_auth_header(req.headers), verify=SSL_VERIFY)
    r_json = r.json()

    raw_vulnerabilities = r_json["vulnerabilities"]
    vulnerabilities = []
    for raw_vulnerability in raw_vulnerabilities:
        vulnerabilities.append(Vulnerability(
            count=raw_vulnerability["count"],
            plugin_name=raw_vulnerability["plugin_name"],
            severity=raw_vulnerability["severity"],
            plugin_family=raw_vulnerability["plugin_family"],
            )
        )

    raw_hosts = r_json["hosts"]
    hosts = []
    for raw_host in raw_hosts:
        hosts.append(ScanResultHost(
            totalchecksconsidered=raw_host["totalchecksconsidered"],
            numchecksconsidered=raw_host["numchecksconsidered"],
            host_id=raw_host["host_id"],
            hostname=raw_host["hostname"],
            score=raw_host["score"],
            critical=raw_host["critical"],
            high=raw_host["high"],
            medium=raw_host["medium"],
            low=raw_host["low"],
            info=raw_host["info"],
            )
        )
    
    return ScanResult(
        hosts=hosts,
        vulnerabilities=vulnerabilities,
    )

