import json
import os
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from openai import OpenAI
from app.services.governed_runner import execute_registered_action

APP_VERSION = "v001"
ADELAIDE_TZ = ZoneInfo("Australia/Adelaide")

ADMIN_USER = os.getenv("DGEM_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("DGEM_ADMIN_PASSWORD", "")
SESSION_SECRET = os.getenv("DGEM_SESSION_SECRET", "dev-only-change-me")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.5")
API_AUDIT_LOG = Path("/data/logs/api_audit_log.jsonl")

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

app.mount("/static", StaticFiles(directory="/app/app/static"), name="static")


def current_user(request: Request):
    return request.session.get("user")


def write_api_audit(record: dict):
    API_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    enriched = {
        "audit_id": str(uuid.uuid4()),
        "timestamp": datetime.now(ADELAIDE_TZ).isoformat(),
        **record
    }
    with API_AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(enriched, ensure_ascii=False) + "\n")
    return enriched["audit_id"]


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
            "timestamp": datetime.now(ADELAIDE_TZ).isoformat(),
            "active_top": "Home"
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


@app.get("/api/chat/test")
def api_chat_test(request: Request):
    user = current_user(request)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    request_id = str(uuid.uuid4())

    if not OPENAI_API_KEY:
        audit_id = write_api_audit({
            "request_id": request_id,
            "actor": user.get("username"),
            "route": "/api/chat/test",
            "status": "blocked",
            "reason": "OPENAI_API_KEY missing"
        })
        return {
            "status": "blocked",
            "request_id": request_id,
            "audit_id": audit_id,
            "message": "OPENAI_API_KEY is not configured."
        }

    prompt = (
        "Reply in one short sentence. "
        "Confirm that the DG-E&M JCS-admin protected API integration test is working. "
        "Do not suggest actions."
    )

    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        response = client.responses.create(
            model=OPENAI_MODEL,
            input=prompt
        )

        output_text = getattr(response, "output_text", "")

        audit_id = write_api_audit({
            "request_id": request_id,
            "actor": user.get("username"),
            "route": "/api/chat/test",
            "status": "success",
            "model": OPENAI_MODEL,
            "response_chars": len(output_text)
        })

        return {
            "status": "success",
            "request_id": request_id,
            "audit_id": audit_id,
            "model": OPENAI_MODEL,
            "response": output_text
        }

    except Exception as exc:
        audit_id = write_api_audit({
            "request_id": request_id,
            "actor": user.get("username"),
            "route": "/api/chat/test",
            "status": "error",
            "model": OPENAI_MODEL,
            "error_type": type(exc).__name__,
            "error_message": str(exc)[:300]
        })

        return {
            "status": "error",
            "request_id": request_id,
            "audit_id": audit_id,
            "model": OPENAI_MODEL,
            "error_type": type(exc).__name__,
            "message": "API test failed. See server audit log for details."
        }


@app.get("/runner/test")
def runner_test(request: Request):
    user = current_user(request)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    result = execute_registered_action(
        action_id="runner_echo_test_v001",
        actor=user
    )

    return {
        "status": result.get("status"),
        "run_id": result.get("run_id"),
        "action_id": result.get("action_id"),
        "actor": result.get("actor"),
        "return_code": result.get("return_code"),
        "stdout": result.get("stdout"),
        "stderr": result.get("stderr"),
        "duration_ms": result.get("duration_ms"),
        "audit_log": "data/logs/runner_audit_log.jsonl"
    }


# WEB_WORKFLOW_SHELL_V001_START

def card(icon, title, href, text, status="", status_class="blue", klass=""):
    return {
        "icon": icon,
        "title": title,
        "href": href,
        "text": text,
        "status": status,
        "status_class": status_class,
        "class": klass
    }


WEB_PAGES = {
    "governance": {
        "active_top": "Governance",
        "icon": "⚖️",
        "title": "Governance",
        "subtitle": "Rules, verification, lifecycle controls, decisions, and registries.",
        "tabs": [
            {"label": "AI Rules", "href": "/governance/ai-rules"},
            {"label": "Truth Verification", "href": "/governance/truth-verification"},
            {"label": "Lifecycle", "href": "/governance/lifecycle"},
            {"label": "Decision Register", "href": "/governance/decision-register"},
            {"label": "Registries", "href": "/governance/registries"},
        ],
        "cards": [
            card("🤖", "AI Rules", "/governance/ai-rules", "Define what AI may explain, propose, and request — but not directly execute.", "Defined", "green"),
            card("✅", "Truth Verification", "/governance/truth-verification", "Verified data, source authority, evidence requirements, and truth checks.", "Planned", "yellow"),
            card("🔁", "Lifecycle", "/governance/lifecycle", "Discover, Establish, Implement, Manage lifecycle stage controls.", "Establish", "blue"),
            card("📘", "Decision Register", "/governance/decision-register", "Project decisions, reasons, and governance commitments.", "Active", "green"),
            card("🗂️", "Registries", "/governance/registries", "Action, script, hardware, metric, widget, and rule registries.", "Started", "green"),
        ],
        "notes": ["Governance defines what the system is allowed to believe and do."]
    },
    "governance/ai-rules": {"active_top": "Governance", "icon": "🤖", "title": "AI Rules", "subtitle": "AI is an assistant and reasoning component, not the source of truth.", "tabs": [], "cards": [card("🧭", "Boundary Rule", "/governance", "AI may request governed actions, but all actions must pass through registered tools and runner boundaries.", "Active", "green")], "notes": []},
    "governance/truth-verification": {"active_top": "Governance", "icon": "✅", "title": "Truth Verification", "subtitle": "Verified evidence before state changes or alarms.", "tabs": [], "cards": [card("📎", "Evidence First", "/governance", "Truth comes from verified records, source authority, and data quality checks.", "Planned", "yellow")], "notes": []},
    "governance/lifecycle": {"active_top": "Governance", "icon": "🔁", "title": "Lifecycle", "subtitle": "Discover → Establish → Implement → Manage.", "tabs": [], "cards": [card("🏗️", "Current Stage", "/dashboard", "The current project stage is Establish.", "Establish", "blue")], "notes": []},
    "governance/decision-register": {"active_top": "Governance", "icon": "📘", "title": "Decision Register", "subtitle": "Project decisions and reasons.", "tabs": [], "cards": [card("📄", "Git-backed Docs", "/dashboards/docs", "Decision files are maintained in docs and change_log.", "Active", "green")], "notes": []},
    "governance/registries": {"active_top": "Governance", "icon": "🗂️", "title": "Registries", "subtitle": "Controlled definitions for actions, scripts, metrics, widgets, and rules.", "tabs": [], "cards": [card("▶️", "Action Registry", "/setup/scripts-widgets", "Runner actions are selected by registry ID, not free-form commands.", "Started", "green")], "notes": []},

    "dashboards": {
        "active_top": "Dashboards",
        "icon": "📊",
        "title": "Dashboards",
        "subtitle": "Operator-facing current state and evidence views.",
        "tabs": [
            {"label": "Health", "href": "/dashboards/health"},
            {"label": "Inventory", "href": "/dashboards/inventory"},
            {"label": "Audit", "href": "/dashboards/audit"},
            {"label": "Docs", "href": "/dashboards/docs"},
        ],
        "cards": [
            card("🩺", "Health", "/dashboards/health", "Host health, polling, metrics, trends, and future widget state.", "Shell", "yellow"),
            card("🖥️", "Inventory", "/dashboards/inventory", "Known assets, computer profiles, hardware types, and profile status.", "Shell", "yellow"),
            card("📜", "Audit", "/dashboards/audit", "API audit, runner audit, discovery audit, and future state transitions.", "Started", "green"),
            card("📚", "Docs", "/dashboards/docs", "Project docs, design docs, evidence library, and future harvested PDFs.", "Active", "green"),
        ],
        "notes": ["Dashboards are read-facing pages. Actions should live under governed setup or runner pages."]
    },
    "dashboards/health": {"active_top": "Dashboards", "icon": "🩺", "title": "Health Dashboard", "subtitle": "Future host polling and trend page.", "tabs": [], "cards": [card("📈", "Health Trends", "/dashboards", "This will inherit ideas from the existing JCS WebAdmin Health Trends page.", "Planned", "yellow")], "notes": []},
    "dashboards/inventory": {"active_top": "Dashboards", "icon": "🖥️", "title": "Inventory Dashboard", "subtitle": "Known hardware and computer profile register.", "tabs": [], "cards": [card("📋", "Asset Register", "/setup/discovery", "Inventory will be populated from managed discovery and approved profiles.", "Planned", "yellow")], "notes": []},
    "dashboards/audit": {"active_top": "Dashboards", "icon": "📜", "title": "Audit Dashboard", "subtitle": "Evidence trails for API, runner, discovery, and state changes.", "tabs": [], "cards": [card("🤖", "API Audit", "/api/chat/test", "Protected API test writes JSONL audit records.", "Active", "green"), card("▶️", "Runner Audit", "/runner/test", "Governed runner writes JSONL audit records.", "Active", "green")], "notes": []},
    "dashboards/docs": {"active_top": "Dashboards", "icon": "📚", "title": "Docs Dashboard", "subtitle": "Design docs, build docs, and future evidence library.", "tabs": [], "cards": [card("📄", "GitHub Docs", "/setup/github", "Documentation is stored in GitHub-backed project files.", "Active", "green")], "notes": []},

    "setup": {
        "active_top": "Set Up",
        "icon": "🛠️",
        "title": "Set Up",
        "subtitle": "Controlled configuration and onboarding workflows.",
        "tabs": [
            {"label": "Connections", "href": "/setup/connections"},
            {"label": "Discovery", "href": "/setup/discovery"},
            {"label": "Scripts & Widgets", "href": "/setup/scripts-widgets"},
            {"label": "GitHub", "href": "/setup/github"},
            {"label": "Cloudflare", "href": "/setup/cloudflare"},
        ],
        "cards": [
            card("🔌", "Connections", "/setup/connections", "OpenAI, GitHub, Cloudflare, NAS paths, Docker, and future PI/SQL/MQTT/OPC connectors.", "Started", "green"),
            card("🔎", "Discovery", "/setup/discovery", "Managed hardware discovery workflow and future candidate device register.", "Next", "yellow"),
            card("🧩", "Scripts & Widgets", "/setup/scripts-widgets", "Approved scripts, runner actions, widget types, and function blocks.", "Started", "green"),
            card("🐙", "GitHub", "/setup/github", "Website source backup, commit history, tags, and future Backup Now action.", "Green", "green"),
            card("☁️", "Cloudflare", "/setup/cloudflare", "External tunnel/access layer, pending review before exposure.", "Pending", "yellow"),
        ],
        "notes": ["Set Up pages may request actions, but only through registered action IDs and the governed runner."]
    },
    "setup/connections": {"active_top": "Set Up", "icon": "🔌", "title": "Connections", "subtitle": "External and internal connection status.", "tabs": [], "cards": [card("🤖", "OpenAI API", "/ai/api-status", "Protected ChatGPT API route is working.", "Green", "green"), card("🐙", "GitHub", "/setup/github", "Project backup is active.", "Green", "green"), card("🦆", "DuckDB", "/duckdb", "Evidence database layer pending implementation.", "Pending", "yellow"), card("☁️", "Cloudflare", "/setup/cloudflare", "External access layer pending review.", "Pending", "yellow")], "notes": []},
    "setup/discovery": {"active_top": "Set Up", "icon": "🔎", "title": "Discovery", "subtitle": "Managed hardware discovery workflow.", "tabs": [], "cards": [card("➕", "Add New Hardware", "/setup/discovery", "Future page: select hardware type and request an approved discovery workflow.", "Planned", "yellow")], "notes": ["No unmanaged network scanning should be exposed here."]},
    "setup/scripts-widgets": {"active_top": "Set Up", "icon": "🧩", "title": "Scripts & Widgets", "subtitle": "Approved actions, deterministic widgets, and runner controls.", "tabs": [], "cards": [card("▶️", "Runner Test", "/runner/test", "Execute the registered low-risk runner proof action.", "Active", "green"), card("🧠", "Widget Specs", "/setup/scripts-widgets", "Future widget types and widget-instance generation.", "Planned", "yellow")], "notes": []},
    "setup/github": {"active_top": "Set Up", "icon": "🐙", "title": "GitHub Backup", "subtitle": "Website source-code backup, tags, source status, and future Backup Now workflow.", "tabs": [], "cards": [card("📦", "Repository", "/setup/github", "Repo: chris4415/dgem-jcs-admin-fastapi. Branch: main.", "Active", "green"), card("🏷️", "Milestone Tags", "/setup/github", "Foundation, login, API, and runner test tags are pushed.", "Active", "green"), card("💾", "Backup Now", "/setup/github", "Future governed action: github_backup_now_v001.", "Pending", "yellow")], "github_box": True, "notes": ["GitHub backs up source code and docs, not secrets or runtime evidence."]},
    "setup/cloudflare": {"active_top": "Set Up", "icon": "☁️", "title": "Cloudflare", "subtitle": "External access and tunnel setup.", "tabs": [], "cards": [card("🚧", "Tunnel Review", "/security", "Existing cloudflared container should be inspected before exposing this app.", "Pending", "yellow")], "notes": []},

    "ai": {
        "active_top": "AI",
        "icon": "🤖",
        "title": "AI Assistance",
        "subtitle": "Guided assistance, API status, context packets, tool requests, and claim review.",
        "tabs": [
            {"label": "Assistant", "href": "/ai/assistant"},
            {"label": "API Status", "href": "/ai/api-status"},
            {"label": "Context Packets", "href": "/ai/context-packets"},
            {"label": "Tool Requests", "href": "/ai/tool-requests"},
            {"label": "Claim Review", "href": "/ai/claim-review"},
            {"label": "API Audit", "href": "/ai/api-audit"},
        ],
        "cards": [
            card("💬", "Assistant", "/ai/assistant", "Future governed ChatGPT assistance dialog.", "Pending", "yellow"),
            card("✅", "API Status", "/ai/api-status", "Protected API test endpoint is active.", "Green", "green"),
            card("📦", "Context Packets", "/ai/context-packets", "Future bounded context packets for API calls.", "Planned", "yellow"),
            card("🧰", "Tool Requests", "/ai/tool-requests", "Future AI tool-call request review and approval.", "Planned", "yellow"),
            card("🔎", "Claim Review", "/ai/claim-review", "Future unsupported-claim blocking and evidence checks.", "Planned", "yellow"),
        ],
        "assistant_box": True,
        "notes": ["AI may propose. Governed systems decide and execute."]
    },
    "ai/assistant": {"active_top": "AI", "icon": "💬", "title": "AI Assistant", "subtitle": "Future governed ChatGPT dialog.", "tabs": [], "cards": [card("🧭", "Governed Dialog", "/ai", "Assistant interaction will be bounded by context, rules, and audit.", "Pending", "yellow")], "assistant_box": True, "notes": []},
    "ai/api-status": {"active_top": "AI", "icon": "✅", "title": "API Status", "subtitle": "OpenAI API configuration and protected test.", "tabs": [], "cards": [card("🤖", "Chat API Test", "/api/chat/test", "Run protected API test using current model.", "Active", "green")], "notes": []},
    "ai/context-packets": {"active_top": "AI", "icon": "📦", "title": "Context Packets", "subtitle": "Future bounded context control.", "tabs": [], "cards": [card("📦", "Context Builder", "/ai", "Future API context packet builder.", "Planned", "yellow")], "notes": []},
    "ai/tool-requests": {"active_top": "AI", "icon": "🧰", "title": "Tool Requests", "subtitle": "Future tool/action requests from AI.", "tabs": [], "cards": [card("🛂", "Approval Boundary", "/setup/scripts-widgets", "Tool requests must map to registered actions.", "Planned", "yellow")], "notes": []},
    "ai/claim-review": {"active_top": "AI", "icon": "🔎", "title": "Claim Review", "subtitle": "Future unsupported claim blocking.", "tabs": [], "cards": [card("✅", "Evidence Required", "/governance/truth-verification", "AI claims should be checked against evidence and source authority.", "Planned", "yellow")], "notes": []},
    "ai/api-audit": {"active_top": "AI", "icon": "📜", "title": "API Audit", "subtitle": "API audit records.", "tabs": [], "cards": [card("📜", "API Audit Log", "/dashboards/audit", "API calls write JSONL audit records.", "Started", "green")], "notes": []},

    "duckdb": {
        "active_top": "DuckDB",
        "icon": "🦆",
        "title": "DuckDB",
        "subtitle": "Local evidence/context database layer.",
        "tabs": [
            {"label": "Status", "href": "/duckdb/status"},
            {"label": "Query", "href": "/duckdb/query"},
            {"label": "Tables", "href": "/duckdb/tables"},
            {"label": "Views", "href": "/duckdb/views"},
            {"label": "Evidence", "href": "/duckdb/evidence"},
            {"label": "Harvests", "href": "/duckdb/harvests"},
            {"label": "Backups", "href": "/duckdb/backups"},
        ],
        "cards": [
            card("🟡", "Database Status", "/duckdb/status", "DuckDB runtime status page pending implementation.", "Pending", "yellow"),
            card("🔍", "Query", "/duckdb/query", "Future controlled read-only query dialog.", "Pending", "yellow"),
            card("📋", "Tables", "/duckdb/tables", "Future table listing and metadata.", "Planned", "yellow"),
            card("📎", "Evidence", "/duckdb/evidence", "Future evidence and document harvest views.", "Planned", "yellow"),
            card("💾", "Backups", "/duckdb/backups", "Future DuckDB backup and checkpoint status.", "Planned", "yellow"),
        ],
        "notes": ["DuckDB is the evidence/context layer. Initial query access must be read-only and audited."]
    },
    "duckdb/status": {"active_top": "DuckDB", "icon": "🦆", "title": "DuckDB Status", "subtitle": "Future database health and file status.", "tabs": [], "cards": [card("📁", "Database File", "/duckdb", "Future DB path, size, table count, and last write time.", "Pending", "yellow")], "notes": []},
    "duckdb/query": {"active_top": "DuckDB", "icon": "🔍", "title": "DuckDB Query", "subtitle": "Future governed read-only SQL query page.", "tabs": [], "cards": [card("🛂", "Read-only Guard", "/duckdb", "Only read-only queries should be allowed in v001.", "Planned", "yellow")], "query_box": True, "notes": []},
    "duckdb/tables": {"active_top": "DuckDB", "icon": "📋", "title": "DuckDB Tables", "subtitle": "Future table listing.", "tabs": [], "cards": [card("📋", "Table Register", "/duckdb", "Future table and schema view.", "Planned", "yellow")], "notes": []},
    "duckdb/views": {"active_top": "DuckDB", "icon": "👁️", "title": "DuckDB Views", "subtitle": "Future evidence/context views.", "tabs": [], "cards": [card("👁️", "Views", "/duckdb", "Future curated evidence views.", "Planned", "yellow")], "notes": []},
    "duckdb/evidence": {"active_top": "DuckDB", "icon": "📎", "title": "DuckDB Evidence", "subtitle": "Future evidence records.", "tabs": [], "cards": [card("📎", "Evidence Records", "/duckdb", "Future document harvest and audit evidence summaries.", "Planned", "yellow")], "notes": []},
    "duckdb/harvests": {"active_top": "DuckDB", "icon": "🌾", "title": "DuckDB Harvests", "subtitle": "Future document/data harvest status.", "tabs": [], "cards": [card("🌾", "Harvest Jobs", "/duckdb", "Future harvest register and run status.", "Planned", "yellow")], "notes": []},
    "duckdb/backups": {"active_top": "DuckDB", "icon": "💾", "title": "DuckDB Backups", "subtitle": "Future DuckDB backup status.", "tabs": [], "cards": [card("💾", "Runtime Backup", "/duckdb", "DuckDB backups belong to NAS/runtime backup, not GitHub.", "Planned", "yellow")], "notes": []},

    "punchlist": {"active_top": "Punchlist", "icon": "✅", "title": "Punchlist", "subtitle": "Build phases, milestones, Git tags, and next actions.", "tabs": [], "cards": [card("🏗️", "Foundation", "/dashboard", "FastAPI, Caddy, Docker, GitHub.", "Complete", "green"), card("🔐", "Security Login", "/security", "Session login and protected routes.", "Complete", "green"), card("🤖", "Chat API", "/ai/api-status", "Protected ChatGPT API test and audit log.", "Complete", "green"), card("▶️", "Governed Runner", "/setup/scripts-widgets", "Registered runner action and audit log.", "Complete", "green"), card("🧭", "Web Workflow Shell", "/dashboard", "Level One / Level Two webpage workflow structure.", "In Progress", "yellow"), card("🦆", "DuckDB", "/duckdb", "Evidence/context database layer.", "Pending", "yellow")], "notes": ["Punchlist is the project control layer."]},

    "security": {
        "active_top": "Security",
        "icon": "🔐",
        "title": "Security",
        "subtitle": "Identity, access, secrets, Cloudflare, and service account controls.",
        "tabs": [
            {"label": "Users & Roles", "href": "/security/users"},
            {"label": "Sessions", "href": "/security/sessions"},
            {"label": "Secrets", "href": "/security/secrets"},
            {"label": "Service Accounts", "href": "/security/service-accounts"},
            {"label": "Access Policies", "href": "/security/access-policies"},
        ],
        "cards": [card("👤", "Users & Roles", "/security/users", "Current session identity and future role management.", "Started", "green"), card("🔑", "Secrets", "/security/secrets", "API keys and session secrets stay in .env and outside Git.", "Active", "green"), card("☁️", "Access Policies", "/security/access-policies", "Cloudflare Access and future external access policy.", "Pending", "yellow"), card("🧾", "Whoami", "/security/whoami", "Current authenticated session JSON.", "Active", "green")],
        "notes": ["Security enforces access. Governance defines the rules."]
    },
    "security/users": {"active_top": "Security", "icon": "👤", "title": "Users & Roles", "subtitle": "Current user and future role management.", "tabs": [], "cards": [card("🧾", "Whoami", "/security/whoami", "View current authenticated user context.", "Active", "green")], "notes": []},
    "security/sessions": {"active_top": "Security", "icon": "🕓", "title": "Sessions", "subtitle": "Current and future session controls.", "tabs": [], "cards": [card("🚪", "Logout", "/logout", "End the current session.", "Active", "green")], "notes": []},
    "security/secrets": {"active_top": "Security", "icon": "🔑", "title": "Secrets", "subtitle": "Secrets must stay outside Git.", "tabs": [], "cards": [card("📁", ".env", "/security", "Local .env contains secrets and is ignored by Git.", "Protected", "green"), card("🐙", "GitHub SSH", "/setup/github", "GitHub uses SSH authentication from NAS100.", "Active", "green")], "notes": []},
    "security/service-accounts": {"active_top": "Security", "icon": "🤝", "title": "Service Accounts", "subtitle": "Future DG-E&M service/logon account controls.", "tabs": [], "cards": [card("🧭", "Least Privilege", "/security", "Service accounts must be role-limited and auditable.", "Planned", "yellow")], "notes": []},
    "security/access-policies": {"active_top": "Security", "icon": "🛂", "title": "Access Policies", "subtitle": "Future external access policies.", "tabs": [], "cards": [card("☁️", "Cloudflare Access", "/setup/cloudflare", "Use Cloudflare as external front-door control before exposing remote access.", "Pending", "yellow")], "notes": []},
}


def workflow_page(request: Request, key: str):
    user = current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    page = WEB_PAGES.get(key)
    if not page:
        raise HTTPException(status_code=404, detail="Workflow page not found")

    return templates.TemplateResponse(
        request,
        "area_page.html",
        {
            "user": user,
            "version": APP_VERSION,
            "query_box": False,
            "assistant_box": False,
            "github_box": False,
            **page
        }
    )


@app.get("/governance", response_class=HTMLResponse)
def governance_page(request: Request):
    return workflow_page(request, "governance")


@app.get("/governance/{subpage}", response_class=HTMLResponse)
def governance_subpage(request: Request, subpage: str):
    return workflow_page(request, f"governance/{subpage}")


@app.get("/dashboards", response_class=HTMLResponse)
def dashboards_page(request: Request):
    return workflow_page(request, "dashboards")


@app.get("/dashboards/{subpage}", response_class=HTMLResponse)
def dashboards_subpage(request: Request, subpage: str):
    return workflow_page(request, f"dashboards/{subpage}")


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    return workflow_page(request, "setup")


@app.get("/setup/{subpage}", response_class=HTMLResponse)
def setup_subpage(request: Request, subpage: str):
    return workflow_page(request, f"setup/{subpage}")


@app.get("/ai", response_class=HTMLResponse)
def ai_page(request: Request):
    return workflow_page(request, "ai")


@app.get("/ai/{subpage}", response_class=HTMLResponse)
def ai_subpage(request: Request, subpage: str):
    return workflow_page(request, f"ai/{subpage}")


@app.get("/duckdb", response_class=HTMLResponse)
def duckdb_page(request: Request):
    return workflow_page(request, "duckdb")


@app.get("/duckdb/{subpage}", response_class=HTMLResponse)
def duckdb_subpage(request: Request, subpage: str):
    return workflow_page(request, f"duckdb/{subpage}")


@app.get("/punchlist", response_class=HTMLResponse)
def punchlist_page(request: Request):
    return workflow_page(request, "punchlist")


@app.get("/security", response_class=HTMLResponse)
def security_page(request: Request):
    return workflow_page(request, "security")


@app.get("/security/{subpage}", response_class=HTMLResponse)
def security_subpage(request: Request, subpage: str):
    return workflow_page(request, f"security/{subpage}")

# WEB_WORKFLOW_SHELL_V001_END

