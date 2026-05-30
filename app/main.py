from fastapi import FastAPI
from datetime import datetime
from zoneinfo import ZoneInfo

APP_VERSION = "v001"
ADELAIDE_TZ = ZoneInfo("Australia/Adelaide")

app = FastAPI(
    title="DG-E&M JCS-admin FastAPI",
    version=APP_VERSION,
    description="Greenfield DG-E&M managed discovery, governed execution, evidence logging, and widget specification system."
)


@app.get("/")
def home():
    return {
        "system": "DG-E&M JCS-admin FastAPI",
        "version": APP_VERSION,
        "status": "running",
        "stage": "environment-foundation",
        "purpose": [
            "managed IT hardware discovery",
            "governed runner control",
            "evidence logging",
            "widget specification generation",
            "future ChatGPT API orchestration"
        ]
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(ADELAIDE_TZ).isoformat(),
        "timezone": "Australia/Adelaide"
    }


@app.get("/environment")
def environment():
    return {
        "project": "DG-E&M",
        "component": "jcs-admin-fastapi",
        "build": APP_VERSION,
        "mode": "greenfield"
    }
