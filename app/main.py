import os
import secrets
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

APP_VERSION = "v001"
ADELAIDE_TZ = ZoneInfo("Australia/Adelaide")

ADMIN_USER = os.getenv("DGEM_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("DGEM_ADMIN_PASSWORD", "")
SESSION_SECRET = os.getenv("DGEM_SESSION_SECRET", "dev-only-change-me")

app = FastAPI(
    title="DG-E&M JCS-admin FastAPI",
    version=APP_VERSION,
    description="Greenfield DG-E&M managed discovery, governed execution, evidence logging, and widget specification system."
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=False
)

templates = Jinja2Templates(directory="/app/app/templates")


def current_user(request: Request):
    return request.session.get("user")


@app.get("/")
def home():
    return {
        "system": "DG-E&M JCS-admin FastAPI",
        "version": APP_VERSION,
        "status": "running",
        "stage": "security-token-login-foundation",
        "login": "/login",
        "dashboard": "/dashboard"
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


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if current_user(request):
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": None,
            "version": APP_VERSION
        }
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    valid_user = secrets.compare_digest(username, ADMIN_USER)
    valid_password = secrets.compare_digest(password, ADMIN_PASSWORD)

    if valid_user and valid_password:
        request.session["user"] = {
            "username": username,
            "role": "admin",
            "login_time": datetime.now(ADELAIDE_TZ).isoformat()
        }
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": "Invalid username or password",
            "version": APP_VERSION
        },
        status_code=401
    )


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "version": APP_VERSION,
            "timestamp": datetime.now(ADELAIDE_TZ).isoformat()
        }
    )


@app.get("/security/whoami")
def whoami(request: Request):
    user = current_user(request)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return {
        "authenticated": True,
        "user": user,
        "timestamp": datetime.now(ADELAIDE_TZ).isoformat()
    }
