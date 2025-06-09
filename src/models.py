from pydantic import BaseModel

class GetSessionTokenRequest(BaseModel):
    username: str
    password: str

class Folder(BaseModel):
    id: int
    name: str
    type: str
    default_tag: int
    custom: int
    unread_count: int | None

class CreateFolderRequest(BaseModel):
    name: str

class StartScanRequest(BaseModel):
    target: str
    scan_type: str = "Basic Network Scan"
    scan_name_prefix: str = "nessus-controller"

class StartScanResponse(BaseModel):
    ok: bool
    scan_id: int
    scan_name: str

class ScanTemplate(BaseModel):
    title: str
    uuid: str
    desc: str

class ListScansItem(BaseModel):
    uuid: str
    name: str
    id: int
    scan_type: str
    folder_id: int
    status: str
    creation_date: int

class ScanStatus(BaseModel):
    name: str
    status: str
    targets: str
    policy: str
    policy_template_uuid: str
    folder_id: int
    timestamp: int

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

