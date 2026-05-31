import json
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ADELAIDE_TZ = ZoneInfo("Australia/Adelaide")

ACTION_REGISTRY_PATH = Path("/registries/action_registry/actions_v001.json")
RUNNER_AUDIT_LOG = Path("/data/logs/runner_audit_log.jsonl")


def _now():
    return datetime.now(ADELAIDE_TZ).isoformat()


def _load_registry():
    with ACTION_REGISTRY_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_audit(record: dict):
    RUNNER_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with RUNNER_AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def execute_registered_action(action_id: str, actor: dict):
    requested_at = _now()
    run_id = str(uuid.uuid4())

    registry = _load_registry()
    action = registry.get("actions", {}).get(action_id)

    if not action:
        record = {
            "run_id": run_id,
            "action_id": action_id,
            "actor": actor.get("username"),
            "role": actor.get("role"),
            "requested_at": requested_at,
            "started_at": None,
            "finished_at": _now(),
            "status": "rejected",
            "reason": "action_id not found in registry",
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "timeout_seconds": None
        }
        _write_audit(record)
        return record

    if not action.get("enabled", False):
        record = {
            "run_id": run_id,
            "action_id": action_id,
            "actor": actor.get("username"),
            "role": actor.get("role"),
            "requested_at": requested_at,
            "started_at": None,
            "finished_at": _now(),
            "status": "rejected",
            "reason": "action disabled",
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "timeout_seconds": action.get("timeout_seconds")
        }
        _write_audit(record)
        return record

    command = action.get("command")
    timeout_seconds = int(action.get("timeout_seconds", 5))

    if not isinstance(command, list) or not command:
        record = {
            "run_id": run_id,
            "action_id": action_id,
            "actor": actor.get("username"),
            "role": actor.get("role"),
            "requested_at": requested_at,
            "started_at": None,
            "finished_at": _now(),
            "status": "rejected",
            "reason": "invalid registered command",
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "timeout_seconds": timeout_seconds
        }
        _write_audit(record)
        return record

    started_at = _now()
    start = time.monotonic()

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False
        )

        finished_at = _now()
        duration_ms = int((time.monotonic() - start) * 1000)

        status = "success" if completed.returncode == 0 else "failed"

        record = {
            "run_id": run_id,
            "action_id": action_id,
            "actor": actor.get("username"),
            "role": actor.get("role"),
            "requested_at": requested_at,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": status,
            "return_code": completed.returncode,
            "stdout": completed.stdout[:4000],
            "stderr": completed.stderr[:4000],
            "duration_ms": duration_ms,
            "timeout_seconds": timeout_seconds
        }

    except subprocess.TimeoutExpired as exc:
        finished_at = _now()
        duration_ms = int((time.monotonic() - start) * 1000)

        record = {
            "run_id": run_id,
            "action_id": action_id,
            "actor": actor.get("username"),
            "role": actor.get("role"),
            "requested_at": requested_at,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": "timeout",
            "return_code": None,
            "stdout": (exc.stdout or "")[:4000],
            "stderr": (exc.stderr or "")[:4000],
            "duration_ms": duration_ms,
            "timeout_seconds": timeout_seconds
        }

    except Exception as exc:
        finished_at = _now()
        duration_ms = int((time.monotonic() - start) * 1000)

        record = {
            "run_id": run_id,
            "action_id": action_id,
            "actor": actor.get("username"),
            "role": actor.get("role"),
            "requested_at": requested_at,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": "error",
            "return_code": None,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {str(exc)[:300]}",
            "duration_ms": duration_ms,
            "timeout_seconds": timeout_seconds
        }

    _write_audit(record)
    return record
