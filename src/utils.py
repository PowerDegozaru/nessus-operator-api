import datetime as dt
import uuid

def build_scan_name(prefix: str = "Test") -> str:
    now = dt.datetime.now().astimezone()
    return f"{prefix}-{now:%Y%m%d-%H%M}"

def generate_uuid() -> str:
    return str(uuid.uuid4())
