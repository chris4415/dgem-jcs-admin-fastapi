#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

DEFAULT_DB = "data/duckdb/dgem_core.duckdb"
MIGRATION_ID = "05D_api_widget_packet_schema_v001"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def insert_if_missing(con, table: str, key_column: str, key_value: str, row: dict) -> None:
    count = con.execute(
        f"SELECT COUNT(*) FROM dgem.{table} WHERE {key_column} = ?",
        [key_value],
    ).fetchone()[0]

    if count:
        return

    columns = list(row.keys())
    placeholders = ", ".join(["?"] * len(columns))
    column_sql = ", ".join(columns)

    con.execute(
        f"INSERT INTO dgem.{table} ({column_sql}) VALUES ({placeholders})",
        [row[c] for c in columns],
    )


def create_tables(con) -> None:
    con.execute("CREATE SCHEMA IF NOT EXISTS dgem")

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.api_widget_registry (
        widget_id VARCHAR PRIMARY KEY,
        widget_name VARCHAR,
        task_type VARCHAR,
        lifecycle_stage VARCHAR,
        purpose VARCHAR,
        risk_level VARCHAR,
        status VARCHAR,
        allowed_outputs_json VARCHAR,
        forbidden_actions_json VARCHAR,
        created_at TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.api_analysis_packet (
        packet_id VARCHAR PRIMARY KEY,
        widget_id VARCHAR,
        task_type VARCHAR,
        lifecycle_stage VARCHAR,
        source_table VARCHAR,
        source_record_id VARCHAR,
        facts_json VARCHAR,
        rules_json VARCHAR,
        allowed_actions_json VARCHAR,
        forbidden_actions_json VARCHAR,
        evidence_quality VARCHAR,
        created_by VARCHAR,
        created_at TIMESTAMP,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.api_analysis_result (
        result_id VARCHAR PRIMARY KEY,
        packet_id VARCHAR,
        widget_id VARCHAR,
        model VARCHAR,
        response_json VARCHAR,
        summary VARCHAR,
        severity_assessment VARCHAR,
        recommended_action_ids_json VARCHAR,
        audit_id VARCHAR,
        created_at TIMESTAMP,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.api_widget_recommendation (
        recommendation_id VARCHAR PRIMARY KEY,
        result_id VARCHAR,
        packet_id VARCHAR,
        widget_id VARCHAR,
        action_id VARCHAR,
        recommendation_type VARCHAR,
        reason VARCHAR,
        risk_level VARCHAR,
        requires_approval BOOLEAN,
        status VARCHAR,
        created_at TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.api_widget_schedule (
        schedule_id VARCHAR PRIMARY KEY,
        widget_id VARCHAR,
        schedule_name VARCHAR,
        task_type VARCHAR,
        schedule_type VARCHAR,
        schedule_expression VARCHAR,
        enabled BOOLEAN,
        last_run_at TIMESTAMP,
        next_run_at TIMESTAMP,
        created_at TIMESTAMP,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.api_widget_run (
        run_id VARCHAR PRIMARY KEY,
        schedule_id VARCHAR,
        widget_id VARCHAR,
        started_at TIMESTAMP,
        finished_at TIMESTAMP,
        status VARCHAR,
        packet_id VARCHAR,
        result_id VARCHAR,
        error_message VARCHAR,
        notes VARCHAR
    )
    """)


def create_views(con) -> None:
    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_api_widget_registry AS
    SELECT
        widget_id,
        widget_name,
        task_type,
        lifecycle_stage,
        risk_level,
        status,
        purpose
    FROM dgem.api_widget_registry
    ORDER BY widget_id
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_api_analysis_packets_pending AS
    SELECT
        packet_id,
        widget_id,
        task_type,
        lifecycle_stage,
        source_table,
        source_record_id,
        evidence_quality,
        created_by,
        created_at,
        status
    FROM dgem.api_analysis_packet
    WHERE status IN ('created', 'pending', 'queued')
    ORDER BY created_at DESC
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_api_analysis_results_latest AS
    WITH ranked AS (
        SELECT
            *,
            ROW_NUMBER() OVER (
                PARTITION BY packet_id
                ORDER BY created_at DESC
            ) AS rn
        FROM dgem.api_analysis_result
    )
    SELECT * EXCLUDE (rn)
    FROM ranked
    WHERE rn = 1
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_api_widget_schedule_status AS
    SELECT
        s.schedule_id,
        s.widget_id,
        r.widget_name,
        s.schedule_name,
        s.task_type,
        s.schedule_type,
        s.schedule_expression,
        s.enabled,
        s.last_run_at,
        s.next_run_at,
        s.status
    FROM dgem.api_widget_schedule s
    LEFT JOIN dgem.api_widget_registry r
        ON s.widget_id = r.widget_id
    ORDER BY s.schedule_id
    """)


def seed_widgets(con) -> None:
    ts = now_iso()

    allowed_outputs = """{
  "allowed": [
    "explain_current_state",
    "summarise_evidence",
    "identify_missing_evidence",
    "prioritise_review",
    "recommend_registered_action_ids",
    "draft_operator_report"
  ]
}"""

    forbidden_actions = """{
  "forbidden": [
    "approve_assets",
    "create_final_truth",
    "execute_commands",
    "change_switch_or_router_config",
    "start_monitoring_without_approval",
    "invent_missing_evidence",
    "bypass_governed_runner"
  ]
}"""

    widgets = [
        {
            "widget_id": "candidate_asset_api_widget_v001",
            "widget_name": "Candidate Asset API-widget",
            "task_type": "candidate_asset_analysis",
            "lifecycle_stage": "establish",
            "purpose": "Explain candidate asset grouping, classification, risk, and review needs.",
            "risk_level": "low",
        },
        {
            "widget_id": "new_connection_api_widget_v001",
            "widget_name": "New Connection API-widget",
            "task_type": "new_connection_analysis",
            "lifecycle_stage": "establish_manage",
            "purpose": "Analyse newly observed MAC/IP/hostname/interface evidence and recommend onboarding or security-watch steps.",
            "risk_level": "medium",
        },
        {
            "widget_id": "network_stress_api_widget_v001",
            "widget_name": "Network Stress API-widget",
            "task_type": "network_stress_analysis",
            "lifecycle_stage": "manage",
            "purpose": "Analyse bandwidth trends, link degradation, faulty NIC/cable indicators, and DDoS-like traffic patterns from verified telemetry.",
            "risk_level": "medium",
        },
        {
            "widget_id": "unknown_anomaly_api_widget_v001",
            "widget_name": "Unknown Anomaly API-widget",
            "task_type": "unknown_anomaly_analysis",
            "lifecycle_stage": "manage",
            "purpose": "Analyse unusual state changes or behaviour outside known deterministic rules.",
            "risk_level": "medium",
        },
        {
            "widget_id": "port_exposure_api_widget_v001",
            "widget_name": "Port Exposure API-widget",
            "task_type": "port_exposure_analysis",
            "lifecycle_stage": "establish_manage",
            "purpose": "Explain open-port exposure, security risk, and recommended governed review actions.",
            "risk_level": "medium",
        },
        {
            "widget_id": "switch_performance_api_widget_v001",
            "widget_name": "Switch Performance API-widget",
            "task_type": "switch_performance_analysis",
            "lifecycle_stage": "manage",
            "purpose": "Analyse switch-port findings such as 10Gb to 1Gb downgrade, port errors, link flaps, and topology drift.",
            "risk_level": "medium",
        },
        {
            "widget_id": "network_optimisation_api_widget_v001",
            "widget_name": "Network Optimisation API-widget",
            "task_type": "network_optimisation_analysis",
            "lifecycle_stage": "establish_manage",
            "purpose": "Analyse network/router/switch configuration evidence and recommend optimisation review steps.",
            "risk_level": "medium",
        },
    ]

    for w in widgets:
        row = {
            "widget_id": w["widget_id"],
            "widget_name": w["widget_name"],
            "task_type": w["task_type"],
            "lifecycle_stage": w["lifecycle_stage"],
            "purpose": w["purpose"],
            "risk_level": w["risk_level"],
            "status": "active",
            "allowed_outputs_json": allowed_outputs,
            "forbidden_actions_json": forbidden_actions,
            "created_at": ts,
            "notes": "Seeded by 05D API-widget packet schema v001.",
        }
        insert_if_missing(con, "api_widget_registry", "widget_id", row["widget_id"], row)

    schedule_row = {
        "schedule_id": "daily_network_stress_analysis_v001",
        "widget_id": "network_stress_api_widget_v001",
        "schedule_name": "Daily Network Stress Analysis",
        "task_type": "network_stress_analysis",
        "schedule_type": "daily",
        "schedule_expression": "manual_disabled_v001",
        "enabled": False,
        "last_run_at": None,
        "next_run_at": None,
        "created_at": ts,
        "status": "disabled",
        "notes": "Seed only. Scheduler not active in v001.",
    }
    insert_if_missing(
        con,
        "api_widget_schedule",
        "schedule_id",
        schedule_row["schedule_id"],
        schedule_row,
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
            "API-widget packet/result schema",
            now_iso(),
            "runner/approved_scripts/api_widget_packet_schema_v001.py",
            "applied",
            "Created API-widget registry, packet/result, recommendation, schedule, and run tables.",
        ],
    )


def show_summary(con) -> None:
    print("")
    print("DG-E&M API-widget packet schema v001 complete")

    for label, sql in [
        ("api widgets", "SELECT COUNT(*) FROM dgem.api_widget_registry"),
        ("api schedules", "SELECT COUNT(*) FROM dgem.api_widget_schedule"),
        ("api packets", "SELECT COUNT(*) FROM dgem.api_analysis_packet"),
        ("api results", "SELECT COUNT(*) FROM dgem.api_analysis_result"),
    ]:
        print(f"{label}: {con.execute(sql).fetchone()[0]}")

    print("")
    print("Seeded API-widgets:")
    for row in con.execute("""
        SELECT widget_id, task_type, risk_level, status
        FROM dgem.api_widget_registry
        ORDER BY widget_id
    """).fetchall():
        print(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create DG-E&M API-widget packet schema v001")
    parser.add_argument("--db", default=DEFAULT_DB)
    args = parser.parse_args()

    try:
        import duckdb
    except ModuleNotFoundError:
        print("ERROR: Python module duckdb is not installed.")
        return 10

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"ERROR: DuckDB file not found: {db_path}")
        return 2

    con = duckdb.connect(str(db_path))

    create_tables(con)
    create_views(con)
    seed_widgets(con)
    record_migration(con)
    show_summary(con)

    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
