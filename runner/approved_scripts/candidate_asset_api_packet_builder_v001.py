#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_DB = "data/duckdb/dgem_core.duckdb"
MIGRATION_ID = "05E_candidate_asset_api_packet_builder_v001"
WIDGET_ID = "candidate_asset_api_widget_v001"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def make_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


def make_id(prefix: str, *parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return f"{prefix}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def rows_as_dicts(con, sql: str, params=None) -> List[Dict[str, Any]]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def require_widget(con) -> Dict[str, Any]:
    rows = rows_as_dicts(
        con,
        """
        SELECT *
        FROM dgem.api_widget_registry
        WHERE widget_id = ?
        """,
        [WIDGET_ID],
    )

    if not rows:
        raise RuntimeError(f"Required API-widget not found: {WIDGET_ID}")

    return rows[0]


def candidate_query(risk: str, limit: int, candidate_id: str = "") -> tuple[str, list]:
    where = ["COALESCE(review_status, '') <> 'approved'"]
    params: list[Any] = []

    if candidate_id:
        where.append("candidate_asset_id = ?")
        params.append(candidate_id)

    if risk and risk != "all":
        where.append("risk_level = ?")
        params.append(risk)

    sql = f"""
        SELECT *
        FROM dgem.candidate_asset
        WHERE {' AND '.join(where)}
        ORDER BY
            CASE risk_level
                WHEN 'red' THEN 1
                WHEN 'amber' THEN 2
                WHEN 'yellow' THEN 3
                WHEN 'green' THEN 4
                ELSE 5
            END,
            likely_device_type,
            primary_ip
        LIMIT ?
    """
    params.append(limit)

    return sql, params


def get_related_evidence(con, candidate: Dict[str, Any]) -> Dict[str, Any]:
    scan_id = candidate.get("source_scan_id") or ""
    primary_ip = candidate.get("primary_ip") or ""
    primary_mac = candidate.get("primary_mac") or ""

    device_rows = rows_as_dicts(
        con,
        """
        SELECT observed_at, ip_address, hostname, mac_address, manufacturer, status, evidence_text
        FROM dgem.device_observation
        WHERE scan_id = ?
          AND (ip_address = ? OR mac_address = ?)
        ORDER BY ip_address, mac_address
        LIMIT 20
        """,
        [scan_id, primary_ip, primary_mac],
    )

    port_rows = rows_as_dicts(
        con,
        """
        SELECT port, protocol, service_name, service_detail, observed_state, risk_hint
        FROM dgem.port_observation
        WHERE scan_id = ?
          AND (ip_address = ? OR mac_address = ?)
        ORDER BY port
        LIMIT 50
        """,
        [scan_id, primary_ip, primary_mac],
    )

    service_rows = rows_as_dicts(
        con,
        """
        SELECT service_type, service_url, banner, shared_resource, notes
        FROM dgem.service_observation
        WHERE scan_id = ?
          AND (ip_address = ? OR mac_address = ?)
        ORDER BY service_type
        LIMIT 50
        """,
        [scan_id, primary_ip, primary_mac],
    )

    return {
        "device_observations": device_rows,
        "port_observations": port_rows,
        "service_observations": service_rows,
    }


def build_rules(candidate: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "governing_rules": [
            "Raw scan output is evidence, not approved truth.",
            "Candidate asset is interpreted evidence.",
            "Approved asset configuration requires governed review.",
            "IP address is an observation, not the asset identity.",
            "Security watch is the default state during initial baseline.",
            "API-widget analysis is advisory only.",
            "API-widget must recommend registered action IDs only.",
            "API-widget must not approve assets or execute actions.",
        ],
        "risk_interpretation": {
            "red": "requires urgent review or quarantine consideration",
            "amber": "requires review and policy confirmation",
            "yellow": "requires normal review or monitoring consideration",
            "green": "low-risk evidence but still not approved truth",
        },
        "candidate_current_state": {
            "managed_status": candidate.get("managed_status"),
            "review_status": candidate.get("review_status"),
            "security_watch": candidate.get("security_watch"),
            "selected_for_onboarding": candidate.get("selected_for_onboarding"),
        },
    }


def build_allowed_actions(candidate: Dict[str, Any]) -> Dict[str, Any]:
    likely_type = candidate.get("likely_device_type") or "unknown"
    risk = candidate.get("risk_level") or "unknown"

    common_actions = [
        "create_candidate_review_item_v001",
        "assign_to_security_watch_v001",
        "request_human_review_v001",
        "collect_additional_evidence_v001",
    ]

    type_actions = {
        "nas": ["run_nas_detail_probe_v001", "propose_nas_health_profile_v001"],
        "security_camera": ["run_camera_detail_probe_v001", "review_camera_zone_assignment_v001"],
        "vmware_esxi": ["run_esxi_detail_probe_v001", "propose_esxi_health_profile_v001"],
        "virtual_machine_guest": ["run_host_detail_probe_v001"],
        "windows_host": ["run_windows_host_probe_v001", "propose_windows_health_profile_v001"],
        "router_gateway": ["collect_router_status_v001", "review_management_port_exposure_v001"],
        "switch": ["collect_switch_identity_v001", "collect_switch_port_status_v001"],
        "ot_energy": ["run_ot_energy_probe_v001", "review_modbus_exposure_v001"],
        "web_managed_appliance": ["collect_web_management_evidence_v001"],
        "unknown": ["run_light_discovery_probe_v001", "classify_unknown_device_v001"],
    }

    risk_actions = []
    if risk == "red":
        risk_actions = [
            "review_red_security_exposure_v001",
            "recommend_quarantine_review_v001",
        ]
    elif risk == "amber":
        risk_actions = [
            "review_amber_security_exposure_v001",
        ]

    return {
        "allowed_action_ids": common_actions + type_actions.get(likely_type, []) + risk_actions,
        "requires_approval": True,
        "execution_allowed": False,
        "note": "These are recommendation IDs only. The API-widget cannot execute actions.",
    }


def build_forbidden_actions(widget: Dict[str, Any]) -> Dict[str, Any]:
    try:
        base = json.loads(widget.get("forbidden_actions_json") or "{}")
    except json.JSONDecodeError:
        base = {}

    base["hard_forbidden"] = [
        "approve_asset",
        "write_asset_register",
        "execute_command",
        "change_network_configuration",
        "disable_switch_port",
        "move_vlan",
        "start_monitoring",
        "invent_evidence",
        "bypass_governed_runner",
    ]

    return base


def build_packet(candidate: Dict[str, Any], widget: Dict[str, Any], evidence: Dict[str, Any], created_by: str) -> Dict[str, Any]:
    facts = {
        "candidate_asset": {
            "candidate_asset_id": candidate.get("candidate_asset_id"),
            "evidence_group_key": candidate.get("evidence_group_key"),
            "likely_hostname": candidate.get("likely_hostname"),
            "likely_device_type": candidate.get("likely_device_type"),
            "likely_manufacturer": candidate.get("likely_manufacturer"),
            "confidence_score": candidate.get("confidence_score"),
            "managed_status": candidate.get("managed_status"),
            "review_status": candidate.get("review_status"),
            "selected_for_onboarding": candidate.get("selected_for_onboarding"),
            "security_watch": candidate.get("security_watch"),
            "risk_level": candidate.get("risk_level"),
            "discovery_mode": candidate.get("discovery_mode"),
            "baseline_status": candidate.get("baseline_status"),
            "source_scan_id": candidate.get("source_scan_id"),
            "primary_ip": candidate.get("primary_ip"),
            "primary_mac": candidate.get("primary_mac"),
            "port_summary": candidate.get("port_summary"),
            "service_summary": candidate.get("service_summary"),
            "classification_reason": candidate.get("classification_reason"),
            "first_seen": str(candidate.get("first_seen")),
            "last_seen": str(candidate.get("last_seen")),
        },
        "related_evidence": evidence,
        "evidence_statement": "All facts are sourced from DuckDB evidence/config tables. This packet is for analysis only.",
    }

    rules = build_rules(candidate)
    allowed_actions = build_allowed_actions(candidate)
    forbidden_actions = build_forbidden_actions(widget)

    facts_hash = make_hash(facts)
    packet_id = make_id(
        "packet",
        WIDGET_ID,
        candidate.get("candidate_asset_id"),
        candidate.get("source_scan_id"),
        facts_hash,
    )

    return {
        "packet_id": packet_id,
        "widget_id": WIDGET_ID,
        "task_type": widget.get("task_type"),
        "lifecycle_stage": widget.get("lifecycle_stage"),
        "source_table": "candidate_asset",
        "source_record_id": candidate.get("candidate_asset_id"),
        "facts_json": json.dumps(facts, sort_keys=True, default=str),
        "rules_json": json.dumps(rules, sort_keys=True, default=str),
        "allowed_actions_json": json.dumps(allowed_actions, sort_keys=True, default=str),
        "forbidden_actions_json": json.dumps(forbidden_actions, sort_keys=True, default=str),
        "evidence_quality": "imported_scan_evidence",
        "created_by": created_by,
        "created_at": now_iso(),
        "status": "created",
        "notes": "Created by candidate_asset_api_packet_builder_v001. API not called.",
    }


def insert_packet_if_missing(con, packet: Dict[str, Any]) -> int:
    count = con.execute(
        "SELECT COUNT(*) FROM dgem.api_analysis_packet WHERE packet_id = ?",
        [packet["packet_id"]],
    ).fetchone()[0]

    if count:
        return 0

    cols = list(packet.keys())
    con.execute(
        f"INSERT INTO dgem.api_analysis_packet ({', '.join(cols)}) VALUES ({', '.join(['?'] * len(cols))})",
        [packet[c] for c in cols],
    )
    return 1


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
            "Candidate asset API packet builder",
            now_iso(),
            "runner/approved_scripts/candidate_asset_api_packet_builder_v001.py",
            "applied",
            "Builds constrained API-widget packets from candidate asset records. Does not call API.",
        ],
    )


def show_summary(con, inserted: int, considered: int) -> None:
    print("")
    print("DG-E&M Candidate Asset API Packet Builder v001 complete")
    print(f"Candidates considered: {considered}")
    print(f"Packets inserted:      {inserted}")

    print("")
    print("Packet counts by task/status:")
    for row in con.execute("""
        SELECT task_type, status, COUNT(*) AS count
        FROM dgem.api_analysis_packet
        GROUP BY task_type, status
        ORDER BY task_type, status
    """).fetchall():
        print(row)

    print("")
    print("Latest candidate packets:")
    for row in con.execute("""
        SELECT packet_id, source_record_id, evidence_quality, status, created_at
        FROM dgem.api_analysis_packet
        WHERE widget_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    """, [WIDGET_ID]).fetchall():
        print(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build constrained API-widget packets from candidate assets")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--risk", default="red", choices=["red", "amber", "yellow", "green", "all"])
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--candidate-id", default="")
    parser.add_argument("--created-by", default="system")
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

    widget = require_widget(con)

    sql, params = candidate_query(args.risk, args.limit, args.candidate_id)
    candidates = rows_as_dicts(con, sql, params)

    inserted = 0

    for candidate in candidates:
        evidence = get_related_evidence(con, candidate)
        packet = build_packet(candidate, widget, evidence, args.created_by)
        inserted += insert_packet_if_missing(con, packet)

    record_migration(con)
    show_summary(con, inserted, len(candidates))

    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
