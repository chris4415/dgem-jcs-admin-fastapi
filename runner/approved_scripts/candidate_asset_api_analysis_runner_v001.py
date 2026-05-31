#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import hashlib
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_DB = "data/duckdb/dgem_core.duckdb"
DEFAULT_MODEL = os.environ.get("DGEM_OPENAI_MODEL", os.environ.get("OPENAI_MODEL", "gpt-4.1-mini"))
MIGRATION_ID = "05F_candidate_asset_api_analysis_runner_v001"
WIDGET_ID = "candidate_asset_api_widget_v001"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def make_id(prefix: str, *parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return f"{prefix}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def short_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


def rows_as_dicts(con, sql: str, params=None) -> List[Dict[str, Any]]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def load_packet(con, packet_id: str = "") -> Optional[Dict[str, Any]]:
    if packet_id:
        rows = rows_as_dicts(
            con,
            """
            SELECT *
            FROM dgem.api_analysis_packet
            WHERE packet_id = ?
              AND widget_id = ?
            """,
            [packet_id, WIDGET_ID],
        )
    else:
        rows = rows_as_dicts(
            con,
            """
            SELECT *
            FROM dgem.api_analysis_packet
            WHERE widget_id = ?
              AND status IN ('created', 'pending', 'queued')
            ORDER BY created_at ASC
            LIMIT 1
            """,
            [WIDGET_ID],
        )

    return rows[0] if rows else None


def get_widget(con, widget_id: str) -> Dict[str, Any]:
    rows = rows_as_dicts(
        con,
        "SELECT * FROM dgem.api_widget_registry WHERE widget_id = ?",
        [widget_id],
    )
    if not rows:
        raise RuntimeError(f"API-widget not found: {widget_id}")
    return rows[0]


def extract_allowed_action_ids(packet: Dict[str, Any]) -> List[str]:
    try:
        allowed = json.loads(packet.get("allowed_actions_json") or "{}")
    except json.JSONDecodeError:
        return []
    return list(allowed.get("allowed_action_ids") or [])


def build_api_prompt(packet: Dict[str, Any], widget: Dict[str, Any]) -> Dict[str, Any]:
    facts = json.loads(packet.get("facts_json") or "{}")
    rules = json.loads(packet.get("rules_json") or "{}")
    allowed_actions = json.loads(packet.get("allowed_actions_json") or "{}")
    forbidden_actions = json.loads(packet.get("forbidden_actions_json") or "{}")

    return {
        "role": "DG-E&M constrained candidate asset API-widget",
        "task": "Analyse a candidate asset packet and return JSON only.",
        "widget": {
            "widget_id": widget.get("widget_id"),
            "widget_name": widget.get("widget_name"),
            "task_type": widget.get("task_type"),
            "purpose": widget.get("purpose"),
        },
        "packet": {
            "packet_id": packet.get("packet_id"),
            "source_table": packet.get("source_table"),
            "source_record_id": packet.get("source_record_id"),
            "evidence_quality": packet.get("evidence_quality"),
            "created_at": str(packet.get("created_at")),
        },
        "facts": facts,
        "rules": rules,
        "allowed_actions": allowed_actions,
        "forbidden_actions": forbidden_actions,
        "required_output_schema": {
            "summary": "string",
            "severity_assessment": "red|amber|yellow|green|unknown",
            "likely_identity": "string",
            "risk_explanation": "string",
            "missing_evidence": ["string"],
            "recommended_actions": [
                {
                    "action_id": "must be one of allowed_actions.allowed_action_ids",
                    "reason": "string",
                    "risk_level": "low|medium|high|unknown",
                    "requires_approval": True
                }
            ],
            "operator_message": "string",
            "compliance_notes": ["string"]
        },
        "hard_constraints": [
            "Return valid JSON only. No markdown.",
            "Do not approve the asset.",
            "Do not create final truth.",
            "Do not execute commands.",
            "Do not change network configuration.",
            "Do not recommend action IDs outside allowed_actions.allowed_action_ids.",
            "Do not invent facts not present in the packet.",
            "If evidence is missing, list it in missing_evidence."
        ],
    }


def call_openai_responses(api_key: str, model: str, prompt_packet: Dict[str, Any]) -> Dict[str, Any]:
    system_text = (
        "You are a constrained DG-E&M API-widget. "
        "Analyse only the supplied DG-E&M packet. "
        "Return valid JSON only. "
        "Do not approve assets, execute commands, change network configuration, or invent evidence."
    )

    user_text = json.dumps(prompt_packet, sort_keys=True, default=str)

    payload = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": system_text,
            },
            {
                "role": "user",
                "content": user_text,
            },
        ],
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OPENAI_RESPONSES_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"OpenAI API connection error: {e}") from e


def extract_response_text(response: Dict[str, Any]) -> str:
    if isinstance(response.get("output_text"), str) and response["output_text"].strip():
        return response["output_text"].strip()

    parts: List[str] = []

    for item in response.get("output", []) or []:
        if item.get("type") == "message":
            for content in item.get("content", []) or []:
                if isinstance(content, dict):
                    text = content.get("text")
                    if isinstance(text, str):
                        parts.append(text)
                    elif content.get("type") in ("output_text", "text") and isinstance(content.get("text"), str):
                        parts.append(content["text"])

    return "\n".join(parts).strip()


def parse_analysis_json(text: str) -> Dict[str, Any]:
    raw = text.strip()

    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?", "", raw, flags=re.I).strip()
        raw = re.sub(r"```$", "", raw).strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, flags=re.S)
        if match:
            return json.loads(match.group(0))
        raise


def normalise_analysis(analysis: Dict[str, Any], allowed_action_ids: List[str]) -> Dict[str, Any]:
    allowed_set = set(allowed_action_ids)

    summary = str(analysis.get("summary") or "").strip()
    severity = str(analysis.get("severity_assessment") or "unknown").strip().lower()
    if severity not in {"red", "amber", "yellow", "green", "unknown"}:
        severity = "unknown"

    recommended = []
    skipped = []

    for item in analysis.get("recommended_actions") or []:
        if not isinstance(item, dict):
            continue

        action_id = str(item.get("action_id") or "").strip()
        if not action_id:
            continue

        if action_id not in allowed_set:
            skipped.append(action_id)
            continue

        recommended.append({
            "action_id": action_id,
            "reason": str(item.get("reason") or "").strip(),
            "risk_level": str(item.get("risk_level") or "unknown").strip().lower(),
            "requires_approval": bool(item.get("requires_approval", True)),
        })

    return {
        "summary": summary,
        "severity_assessment": severity,
        "likely_identity": str(analysis.get("likely_identity") or "").strip(),
        "risk_explanation": str(analysis.get("risk_explanation") or "").strip(),
        "missing_evidence": list(analysis.get("missing_evidence") or []),
        "recommended_actions": recommended,
        "operator_message": str(analysis.get("operator_message") or "").strip(),
        "compliance_notes": list(analysis.get("compliance_notes") or []),
        "skipped_unregistered_action_ids": skipped,
    }


def insert_result(con, packet: Dict[str, Any], model: str, response_raw: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    response_payload = {
        "analysis": analysis,
        "raw_response_id": response_raw.get("id"),
        "raw_status": response_raw.get("status"),
    }

    result_id = make_id("result", packet["packet_id"], model, short_hash(response_payload))

    count = con.execute(
        "SELECT COUNT(*) FROM dgem.api_analysis_result WHERE result_id = ?",
        [result_id],
    ).fetchone()[0]

    if count:
        return result_id

    recommended_action_ids = [a["action_id"] for a in analysis.get("recommended_actions", [])]

    con.execute(
        """
        INSERT INTO dgem.api_analysis_result
        (result_id, packet_id, widget_id, model, response_json, summary,
         severity_assessment, recommended_action_ids_json, audit_id, created_at, status, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            result_id,
            packet["packet_id"],
            packet["widget_id"],
            model,
            json.dumps(response_payload, sort_keys=True, default=str),
            analysis.get("summary", ""),
            analysis.get("severity_assessment", "unknown"),
            json.dumps(recommended_action_ids, sort_keys=True),
            "",
            now_iso(),
            "created",
            "Created by candidate_asset_api_analysis_runner_v001. Advisory analysis only.",
        ],
    )

    return result_id


def insert_recommendations(con, packet: Dict[str, Any], result_id: str, analysis: Dict[str, Any]) -> int:
    inserted = 0

    for action in analysis.get("recommended_actions", []):
        recommendation_id = make_id(
            "rec",
            result_id,
            packet["packet_id"],
            action.get("action_id"),
            action.get("reason"),
        )

        count = con.execute(
            "SELECT COUNT(*) FROM dgem.api_widget_recommendation WHERE recommendation_id = ?",
            [recommendation_id],
        ).fetchone()[0]

        if count:
            continue

        con.execute(
            """
            INSERT INTO dgem.api_widget_recommendation
            (recommendation_id, result_id, packet_id, widget_id, action_id,
             recommendation_type, reason, risk_level, requires_approval, status, created_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                recommendation_id,
                result_id,
                packet["packet_id"],
                packet["widget_id"],
                action.get("action_id", ""),
                "candidate_asset_action_recommendation",
                action.get("reason", ""),
                action.get("risk_level", "unknown"),
                bool(action.get("requires_approval", True)),
                "created",
                now_iso(),
                "Recommendation only. No action executed.",
            ],
        )
        inserted += 1

    return inserted


def update_packet_status(con, packet_id: str, status: str, note: str) -> None:
    con.execute(
        """
        UPDATE dgem.api_analysis_packet
        SET status = ?,
            notes = COALESCE(notes, '') || '\n' || ?
        WHERE packet_id = ?
        """,
        [status, f"{now_iso()} {note}", packet_id],
    )


def record_migration(con) -> None:
    count = con.execute(
        "SELECT COUNT(*) FROM dgem.schema_migration_log WHERE migration_id = ?",
        [MIGRATION_ID],
    ).fetchone()[0]

    if count:
        return

    con.execute(
        """
        INSERT INTO dgem.schema_migration_log
        (migration_id, version, description, applied_at, script_name, status, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            MIGRATION_ID,
            "v001",
            "Candidate asset API analysis runner",
            now_iso(),
            "runner/approved_scripts/candidate_asset_api_analysis_runner_v001.py",
            "applied",
            "Runs one constrained API-widget packet and stores advisory result/recommendations.",
        ],
    )


def show_result(packet: Dict[str, Any], result_id: str, analysis: Dict[str, Any], rec_count: int) -> None:
    print("")
    print("DG-E&M Candidate Asset API Analysis Runner v001 complete")
    print(f"packet_id:     {packet['packet_id']}")
    print(f"source_record: {packet['source_record_id']}")
    print(f"result_id:     {result_id}")
    print(f"severity:      {analysis.get('severity_assessment')}")
    print(f"recommendations inserted: {rec_count}")
    print("")
    print("summary:")
    print(analysis.get("summary", ""))
    print("")
    print("recommended action IDs:")
    for action in analysis.get("recommended_actions", []):
        print(f"  - {action.get('action_id')}: {action.get('reason')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run constrained API analysis for one candidate asset packet")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--packet-id", default="")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        import duckdb
    except ModuleNotFoundError:
        print("ERROR: Python module duckdb is not installed.", file=sys.stderr)
        return 10

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"ERROR: DuckDB file not found: {db_path}", file=sys.stderr)
        return 2

    con = duckdb.connect(str(db_path))

    packet = load_packet(con, args.packet_id)
    if not packet:
        print("No candidate asset API packets found with status created/pending/queued.", file=sys.stderr)
        con.close()
        return 2

    widget = get_widget(con, packet["widget_id"])
    prompt_packet = build_api_prompt(packet, widget)

    if args.dry_run:
        print("")
        print("DRY RUN ONLY - API not called")
        print(f"packet_id: {packet['packet_id']}")
        print(f"source_record_id: {packet['source_record_id']}")
        print("")
        print(json.dumps(prompt_packet, indent=2, sort_keys=True, default=str)[:4000])
        con.close()
        return 0

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        print("ERROR: OPENAI_API_KEY is not set in this shell/container environment.", file=sys.stderr)
        con.close()
        return 3

    allowed_action_ids = extract_allowed_action_ids(packet)

    try:
        response_raw = call_openai_responses(api_key, args.model, prompt_packet)
        response_text = extract_response_text(response_raw)
        analysis_raw = parse_analysis_json(response_text)
        analysis = normalise_analysis(analysis_raw, allowed_action_ids)

        result_id = insert_result(con, packet, args.model, response_raw, analysis)
        rec_count = insert_recommendations(con, packet, result_id, analysis)

        update_packet_status(
            con,
            packet["packet_id"],
            "analysed",
            f"Analysed by {MIGRATION_ID}; result_id={result_id}",
        )

        record_migration(con)
        show_result(packet, result_id, analysis, rec_count)

    except Exception as e:
        update_packet_status(
            con,
            packet["packet_id"],
            "analysis_failed",
            f"Analysis failed in {MIGRATION_ID}: {e}",
        )
        con.close()
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
