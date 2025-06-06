"""
Simple RESTful Nessus API that makes use of browser-use for any requests that cannot be forwarded to API calls in Nessus Essentials.

If there is a need to call the Nessus APIs, all headers will be forwarded (which includes session token / API keys useful for authentication).
"""

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from pathlib import Path
import tomllib
import requests
import logging
import sys
import asyncio

import browser_tasks
import utils

app = FastAPI()

CONFIG_PATH = (Path(__file__).parent.parent / "config.toml").resolve()
with open(CONFIG_PATH, "rb") as f:
    conf = tomllib.load(f)

NESSUS_URL = conf["nessus"]["url"]  # Actual Nessus API URL
NESSUS_USERNAME = conf["nessus"]["username"]
NESSUS_PASSWORD = conf["nessus"]["password"]

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

# In-memory storage for scan state/logs (swap for Redis/db in production)
scan_store: dict[str, dict[str, str]] = {}


#--------------------------------------------------
class GetSessionTokenRequest(BaseModel):
    username: str
    password: str

@app.post("/session")
def get_session_token(body:GetSessionTokenRequest) -> str:
    """Get session token for authentication to call the other API calls"""
    data = {"username": body.username, "password": body.password}
    r = requests.post(NESSUS_URL + "/session", json=data, verify=SSL_VERIFY)
    if r.status_code != 200:
        return r.json()
    return r.json()["token"]


#--------------------------------------------------
class StartScanRequest(BaseModel):
    target: str
    scan_type: str = "Basic Network Scan"
    scan_name_prefix: str = "Test"

class StartScanResponse(BaseModel):
    ok: bool
    scan_id: str
    scan_name: str

@app.post("/start_scan")
async def start_scan(body: StartScanRequest) -> StartScanResponse:
    scan_name = utils.build_scan_name(body.scan_name_prefix)
    scan_id = utils.generate_uuid()
    try:
        log = await browser_tasks.scan_operator_run(body.target, body.scan_type, scan_name)
    except Exception as exc:
        logging.exception("Scan failed")
        raise HTTPException(status_code=500, detail=str(exc))

    scan_store[scan_id] = {
        "scan_name": scan_name,
        "target": body.target,
        "scan_type": body.scan_type,
        "status": "complete",
        "log": log
    }
    return StartScanResponse(ok=True, scan_id=scan_id, scan_name=scan_name)


#--------------------------------------------------
class ScanTemplate(BaseModel):
    title: str
    uuid: str
    desc: str
    
@app.get("/list_scan_templates")
def list_scan_templates(req: Request) -> list[ScanTemplate]:
    res = []

    r = requests.get(NESSUS_URL + "/editor/scan/templates", headers=req.headers, verify=SSL_VERIFY)
    r_json = r.json()

    raw_templates = r_json["templates"]
    for raw_template in raw_templates:
        res.append(ScanTemplate(
            title = raw_template["title"],
            uuid = raw_template["uuid"],
            desc = raw_template["desc"],
            )
        )
    return res


#--------------------------------------------------
class ListScansItem(BaseModel):
    uuid: str
    name: str
    id: int
    scan_type: str
    folder_id: int
    status: str
    creation_date: int

@app.get("/list_scans")
def list_scans(req: Request, folder_id: int | None = None) -> list[ListScansItem]:
    params = {}
    if folder_id is not None:
        params["folder_id"] = folder_id
    r = requests.get(NESSUS_URL + "/scans", params=params, headers=req.headers, verify=SSL_VERIFY)
    r_json = r.json()

    raw_scans = r_json["scans"]
    res = []

    for raw_scan in raw_scans:
        res.append(ListScansItem(
            name = raw_scan["name"],
            scan_type = raw_scan["scan_type"],
            id = raw_scan["id"],
            folder_id = raw_scan["folder_id"],
            status = raw_scan["status"],
            uuid = raw_scan["uuid"],
            creation_date = raw_scan["creation_date"],
            )
        )
    return res


#--------------------------------------------------
class ScanStatus(BaseModel):
    name: str
    status: str
    targets: str
    policy: str
    policy_template_uuid: str
    folder_id: int
    timestamp: int

@app.get("/scan_status")
def get_scan_status(req: Request, scan_id: int) -> ScanStatus:
    r = requests.get(NESSUS_URL + f"/scans/{scan_id}", headers=req.headers, verify=SSL_VERIFY)
    r_json = r.json()

    info = r_json["info"]

    return ScanStatus(
        name = info["name"],
        status = info["status"],
        targets = info["targets"],
        policy = info["policy"],
        policy_template_uuid= info["policy_template_uuid"],
        folder_id = info["folder_id"],
        timestamp = info["timestamp"],
    )


#--------------------------------------------------
class Vulnerability(BaseModel):
    count: int
    plugin_name: str
    severity: int
    plugin_family: str

class ScanResultHost(BaseModel):
    totalchecksconsidered: int
    numchecksconsidered: int
    host_id: int
    hostname: str
    score: int
    critical: int
    high: int
    medium: int
    low: int
    info: int

class ScanResult(BaseModel):
    hosts: list[ScanResultHost]
    vulnerabilities: list[Vulnerability]

@app.get("/scan_results")
def get_scan_results(req: Request, scan_id: int):
    r = requests.get(NESSUS_URL + f"/scans/{scan_id}", headers=req.headers, verify=SSL_VERIFY)
    r_json = r.json()

    raw_vulnerabilities = r_json["vulnerabilities"]
    vulnerabilities = []
    for raw_vulnerability in raw_vulnerabilities:
        vulnerabilities.append(Vulnerability(
            count = raw_vulnerability["count"],
            plugin_name = raw_vulnerability["plugin_name"],
            severity = raw_vulnerability["severity"],
            plugin_family = raw_vulnerability["plugin_family"],
            )
        )

    raw_hosts = r_json["hosts"]
    hosts = []
    for raw_host in raw_hosts:
        hosts.append(ScanResultHost(
            totalchecksconsidered = raw_host["totalchecksconsidered"],
            numchecksconsidered = raw_host["numchecksconsidered"],
            host_id = raw_host["host_id"],
            hostname = raw_host["hostname"],
            score = raw_host["score"],
            critical = raw_host["critical"],
            high = raw_host["high"],
            medium = raw_host["medium"],
            low = raw_host["low"],
            info = raw_host["info"],
            )
        )
    
    return ScanResult(
        hosts = hosts,
        vulnerabilities = vulnerabilities,
    )
