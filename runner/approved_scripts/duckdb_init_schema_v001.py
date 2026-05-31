#!/usr/bin/env python3
"""
DG-E&M DuckDB Foundation Schema v001

Creates the local DG-E&M evidence/configuration database.

Default database:
  data/duckdb/dgem_core.duckdb

Boundary:
  This script creates schema only.
  It does not import scans.
  It does not approve assets.
  It does not start monitoring.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path


MIGRATION_ID = "05A_duckdb_foundation_schema_v001"
DEFAULT_DB = "data/duckdb/dgem_core.duckdb"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def table_exists(con, schema: str, table: str) -> bool:
    rows = con.execute(
        """
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = ? AND table_name = ?
        """,
        [schema, table],
    ).fetchone()
    return bool(rows and rows[0])


def create_schema(con) -> None:
    con.execute("CREATE SCHEMA IF NOT EXISTS dgem")

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.schema_migration_log (
        migration_id VARCHAR PRIMARY KEY,
        version VARCHAR,
        description VARCHAR,
        applied_at TIMESTAMP,
        script_name VARCHAR,
        status VARCHAR,
        detail VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.evidence_source (
        source_id VARCHAR PRIMARY KEY,
        source_type VARCHAR,
        source_name VARCHAR,
        source_path VARCHAR,
        authority_level VARCHAR,
        trust_level VARCHAR,
        status VARCHAR,
        created_at TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.raw_import_file (
        file_id VARCHAR PRIMARY KEY,
        source_id VARCHAR,
        file_path VARCHAR,
        file_name VARCHAR,
        file_type VARCHAR,
        file_hash VARCHAR,
        imported_at TIMESTAMP,
        imported_by VARCHAR,
        parse_status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.scan_snapshot (
        scan_id VARCHAR PRIMARY KEY,
        source_id VARCHAR,
        file_id VARCHAR,
        scan_type VARCHAR,
        scan_scope VARCHAR,
        scan_started_at TIMESTAMP,
        scan_finished_at TIMESTAMP,
        imported_at TIMESTAMP,
        imported_by VARCHAR,
        record_count INTEGER,
        evidence_quality VARCHAR,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.device_observation (
        observation_id VARCHAR PRIMARY KEY,
        scan_id VARCHAR,
        observed_at TIMESTAMP,
        ip_address VARCHAR,
        hostname VARCHAR,
        mac_address VARCHAR,
        manufacturer VARCHAR,
        status VARCHAR,
        vlan_id VARCHAR,
        zone_id VARCHAR,
        device_label VARCHAR,
        evidence_text VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.port_observation (
        port_observation_id VARCHAR PRIMARY KEY,
        scan_id VARCHAR,
        observed_at TIMESTAMP,
        ip_address VARCHAR,
        mac_address VARCHAR,
        port INTEGER,
        protocol VARCHAR,
        service_name VARCHAR,
        service_detail VARCHAR,
        observed_state VARCHAR,
        risk_hint VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.service_observation (
        service_observation_id VARCHAR PRIMARY KEY,
        scan_id VARCHAR,
        observed_at TIMESTAMP,
        ip_address VARCHAR,
        mac_address VARCHAR,
        service_type VARCHAR,
        service_url VARCHAR,
        banner VARCHAR,
        shared_resource VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.candidate_asset (
        candidate_asset_id VARCHAR PRIMARY KEY,
        evidence_group_key VARCHAR,
        likely_hostname VARCHAR,
        likely_device_type VARCHAR,
        likely_manufacturer VARCHAR,
        confidence_score DOUBLE,
        managed_status VARCHAR,
        review_status VARCHAR,
        selected_for_onboarding BOOLEAN,
        security_watch BOOLEAN,
        risk_level VARCHAR,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.asset_register (
        asset_id VARCHAR PRIMARY KEY,
        approved_name VARCHAR,
        asset_type VARCHAR,
        owner VARCHAR,
        custodian VARCHAR,
        zone_id VARCHAR,
        vlan_id VARCHAR,
        monitoring_profile_id VARCHAR,
        approved_status VARCHAR,
        approved_at TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.asset_interface_register (
        interface_id VARCHAR PRIMARY KEY,
        asset_id VARCHAR,
        mac_address VARCHAR,
        ip_address VARCHAR,
        vlan_id VARCHAR,
        zone_id VARCHAR,
        interface_name VARCHAR,
        observed_state VARCHAR,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.zone_register (
        zone_id VARCHAR PRIMARY KEY,
        zone_name VARCHAR,
        purpose VARCHAR,
        trust_level VARCHAR,
        default_policy VARCHAR,
        custodian VARCHAR,
        risk_level VARCHAR,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.vlan_register (
        vlan_id VARCHAR PRIMARY KEY,
        vlan_number INTEGER,
        vlan_name VARCHAR,
        subnet VARCHAR,
        gateway VARCHAR,
        zone_id VARCHAR,
        trust_level VARCHAR,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.policy_matrix (
        policy_id VARCHAR PRIMARY KEY,
        source_zone_id VARCHAR,
        destination_zone_id VARCHAR,
        protocol VARCHAR,
        port INTEGER,
        decision VARCHAR,
        rule_reason VARCHAR,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.port_exposure_register (
        exposure_id VARCHAR PRIMARY KEY,
        asset_id VARCHAR,
        candidate_asset_id VARCHAR,
        ip_address VARCHAR,
        vlan_id VARCHAR,
        zone_id VARCHAR,
        port INTEGER,
        protocol VARCHAR,
        service_name VARCHAR,
        service_detail VARCHAR,
        expected_state VARCHAR,
        observed_state VARCHAR,
        allowed_source_zones VARCHAR,
        risk_level VARCHAR,
        review_status VARCHAR,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.risk_finding (
        finding_id VARCHAR PRIMARY KEY,
        scan_id VARCHAR,
        candidate_asset_id VARCHAR,
        asset_id VARCHAR,
        ip_address VARCHAR,
        mac_address VARCHAR,
        finding_type VARCHAR,
        severity VARCHAR,
        evidence VARCHAR,
        rule_id VARCHAR,
        status VARCHAR,
        created_at TIMESTAMP,
        resolved_at TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.security_watch_register (
        watch_id VARCHAR PRIMARY KEY,
        candidate_asset_id VARCHAR,
        first_seen_scan_id VARCHAR,
        current_status VARCHAR,
        review_status VARCHAR,
        watch_reason VARCHAR,
        zone_id VARCHAR,
        vlan_id VARCHAR,
        risk_level VARCHAR,
        last_seen TIMESTAMP,
        next_scan_due TIMESTAMP,
        owner VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.security_watch_scan_schedule (
        schedule_id VARCHAR PRIMARY KEY,
        watch_id VARCHAR,
        scan_level VARCHAR,
        frequency VARCHAR,
        enabled BOOLEAN,
        last_run TIMESTAMP,
        next_run TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.health_profile_template (
        profile_id VARCHAR PRIMARY KEY,
        device_type VARCHAR,
        profile_name VARCHAR,
        purpose VARCHAR,
        polling_method VARCHAR,
        risk_level VARCHAR,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.health_check_definition (
        check_definition_id VARCHAR PRIMARY KEY,
        profile_id VARCHAR,
        check_name VARCHAR,
        metric_name VARCHAR,
        expected_state VARCHAR,
        severity VARCHAR,
        polling_method VARCHAR,
        status VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.health_check_instance (
        check_instance_id VARCHAR PRIMARY KEY,
        asset_id VARCHAR,
        candidate_asset_id VARCHAR,
        profile_id VARCHAR,
        check_definition_id VARCHAR,
        current_state VARCHAR,
        enabled BOOLEAN,
        created_at TIMESTAMP,
        last_evidence_time TIMESTAMP,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.health_metric_observation (
        metric_observation_id VARCHAR PRIMARY KEY,
        check_instance_id VARCHAR,
        asset_id VARCHAR,
        candidate_asset_id VARCHAR,
        metric_name VARCHAR,
        metric_value VARCHAR,
        metric_unit VARCHAR,
        observed_at TIMESTAMP,
        evidence_source_id VARCHAR,
        quality VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.health_state_current (
        state_id VARCHAR PRIMARY KEY,
        asset_id VARCHAR,
        candidate_asset_id VARCHAR,
        state VARCHAR,
        reason VARCHAR,
        evidence_time TIMESTAMP,
        updated_at TIMESTAMP,
        quality VARCHAR,
        notes VARCHAR
    )
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dgem.health_state_history (
        history_id VARCHAR PRIMARY KEY,
        asset_id VARCHAR,
        candidate_asset_id VARCHAR,
        previous_state VARCHAR,
        new_state VARCHAR,
        reason VARCHAR,
        evidence_time TIMESTAMP,
        changed_at TIMESTAMP,
        notes VARCHAR
    )
    """)


def create_views(con) -> None:
    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_latest_device_observations AS
    WITH ranked AS (
        SELECT
            *,
            ROW_NUMBER() OVER (
                PARTITION BY COALESCE(NULLIF(mac_address, ''), ip_address)
                ORDER BY observed_at DESC
            ) AS rn
        FROM dgem.device_observation
    )
    SELECT * EXCLUDE (rn)
    FROM ranked
    WHERE rn = 1
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_current_open_ports AS
    SELECT
        po.scan_id,
        po.observed_at,
        po.ip_address,
        po.mac_address,
        po.port,
        po.protocol,
        po.service_name,
        po.service_detail,
        po.risk_hint
    FROM dgem.port_observation po
    WHERE LOWER(COALESCE(po.observed_state, 'open')) IN ('open', 'on', 'active')
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_candidate_assets AS
    SELECT
        candidate_asset_id,
        evidence_group_key,
        likely_hostname,
        likely_device_type,
        likely_manufacturer,
        confidence_score,
        managed_status,
        review_status,
        selected_for_onboarding,
        security_watch,
        risk_level,
        first_seen,
        last_seen
    FROM dgem.candidate_asset
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_security_watch AS
    SELECT
        sw.watch_id,
        ca.candidate_asset_id,
        ca.likely_hostname,
        ca.likely_device_type,
        sw.current_status,
        sw.review_status,
        sw.watch_reason,
        sw.risk_level,
        sw.last_seen,
        sw.next_scan_due
    FROM dgem.security_watch_register sw
    LEFT JOIN dgem.candidate_asset ca
        ON sw.candidate_asset_id = ca.candidate_asset_id
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_high_risk_ports AS
    SELECT
        exposure_id,
        asset_id,
        candidate_asset_id,
        ip_address,
        vlan_id,
        zone_id,
        port,
        protocol,
        service_name,
        observed_state,
        expected_state,
        risk_level,
        review_status,
        last_seen
    FROM dgem.port_exposure_register
    WHERE LOWER(COALESCE(risk_level, '')) IN ('high', 'red', 'critical')
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_network_map_nodes AS
    SELECT
        'zone:' || zone_id AS node_id,
        zone_name AS label,
        'zone' AS node_type,
        zone_id,
        NULL AS asset_id,
        NULL AS candidate_asset_id,
        risk_level AS state
    FROM dgem.zone_register

    UNION ALL

    SELECT
        'candidate:' || candidate_asset_id AS node_id,
        COALESCE(NULLIF(likely_hostname, ''), candidate_asset_id) AS label,
        COALESCE(NULLIF(likely_device_type, ''), 'candidate_asset') AS node_type,
        NULL AS zone_id,
        NULL AS asset_id,
        candidate_asset_id,
        risk_level AS state
    FROM dgem.candidate_asset

    UNION ALL

    SELECT
        'asset:' || asset_id AS node_id,
        approved_name AS label,
        asset_type AS node_type,
        zone_id,
        asset_id,
        NULL AS candidate_asset_id,
        approved_status AS state
    FROM dgem.asset_register
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_network_map_edges AS
    SELECT
        'exposure:' || exposure_id AS edge_id,
        COALESCE('asset:' || asset_id, 'candidate:' || candidate_asset_id) AS source_node_id,
        'port:' || protocol || ':' || CAST(port AS VARCHAR) AS target_node_id,
        service_name AS label,
        risk_level AS state,
        review_status
    FROM dgem.port_exposure_register
    """)


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
    values = [row[c] for c in columns]

    con.execute(
        f"INSERT INTO dgem.{table} ({column_sql}) VALUES ({placeholders})",
        values,
    )


def seed_reference_data(con) -> None:
    ts = now_iso()

    evidence_sources = [
        {
            "source_id": "advanced_port_scanner_import",
            "source_type": "import",
            "source_name": "Advanced Port Scanner Export",
            "source_path": "manual upload / imported file",
            "authority_level": "evidence",
            "trust_level": "medium",
            "status": "active",
            "created_at": ts,
            "notes": "External scan export. Evidence only, not approved truth.",
        },
        {
            "source_id": "native_network_scan",
            "source_type": "runner_scan",
            "source_name": "DG-E&M Native Network Discovery Scan",
            "source_path": "runner/approved_scripts",
            "authority_level": "evidence",
            "trust_level": "medium",
            "status": "planned",
            "created_at": ts,
            "notes": "Future governed local scanner.",
        },
        {
            "source_id": "manual_review",
            "source_type": "human_review",
            "source_name": "Governed Manual Review",
            "source_path": "JCS-admin website",
            "authority_level": "approval",
            "trust_level": "high",
            "status": "active",
            "created_at": ts,
            "notes": "Review/approval source for promoted configuration.",
        },
    ]

    for row in evidence_sources:
        insert_if_missing(con, "evidence_source", "source_id", row["source_id"], row)

    zones = [
        ("zone_unknown_quarantine", "Unknown / Quarantine", "Unclassified or unapproved network observations", "low", "deny_by_default", "DG-E&M", "yellow"),
        ("zone_perimeter_gateway", "Perimeter / Gateway", "Routers, firewalls, WAN, DNS/DHCP edge", "high", "restricted", "DG-E&M", "amber"),
        ("zone_management", "Management", "Administrative interfaces and management paths", "high", "restricted", "DG-E&M", "amber"),
        ("zone_core_infrastructure", "Core Infrastructure", "Switches, access points, DNS, DHCP, NTP", "high", "restricted", "DG-E&M", "amber"),
        ("zone_server", "Server", "Windows/Linux servers, SQL, PI, application hosts", "medium", "restricted", "DG-E&M", "yellow"),
        ("zone_storage_backup", "Storage / Backup", "NAS, backup repositories, archive storage", "medium", "restricted", "DG-E&M", "yellow"),
        ("zone_ot_energy", "OT / Energy", "Fronius, Modbus, energy/process devices", "sensitive", "deny_by_default", "DG-E&M", "amber"),
        ("zone_camera_security", "Security / Camera", "Cameras, NVR, RTSP/security devices", "sensitive", "deny_by_default", "DG-E&M", "amber"),
        ("zone_iot_weather", "IoT / Weather", "Weather, smart devices, simple edge devices", "low", "deny_by_default", "DG-E&M", "yellow"),
        ("zone_user_client", "User / Client", "Workstations, laptops, phones, tablets", "medium", "restricted", "DG-E&M", "yellow"),
        ("zone_guest", "Guest", "Guest or transient devices", "low", "deny_by_default", "DG-E&M", "red"),
    ]

    for zone_id, name, purpose, trust, policy, custodian, risk in zones:
        insert_if_missing(
            con,
            "zone_register",
            "zone_id",
            zone_id,
            {
                "zone_id": zone_id,
                "zone_name": name,
                "purpose": purpose,
                "trust_level": trust,
                "default_policy": policy,
                "custodian": custodian,
                "risk_level": risk,
                "status": "active",
                "notes": "Seeded by 05A schema v001.",
            },
        )

    health_profiles = [
        ("profile_unknown_discovery", "unknown", "Unknown Discovery Profile", "Basic visibility and service discovery only", "scan", "yellow"),
        ("profile_router_switch", "router_switch", "Router/Switch Health", "Gateway/switch reachability, management ports, topology evidence", "network", "amber"),
        ("profile_nas", "nas", "NAS Health", "NAS reachability, SMB/HTTP/SSH exposure, future SMART/storage checks", "network_then_api", "yellow"),
        ("profile_windows_server", "windows_server", "Windows Server Health", "Windows/RDP/SMB/IIS reachability, future CPU/RAM/disk/service checks", "network_then_agent", "yellow"),
        ("profile_linux_host", "linux_host", "Linux Host Health", "SSH reachability, future CPU/RAM/disk/service checks", "network_then_ssh", "yellow"),
        ("profile_esxi", "vmware_esxi", "VMware / ESXi Health", "ESXi management reachability and future host/datastore checks", "network_then_api", "amber"),
        ("profile_camera", "security_camera", "Security Camera Health", "HTTP/RTSP reachability, expected camera-zone checks", "network", "amber"),
        ("profile_printer", "printer", "Printer Health", "Print service reachability", "network", "yellow"),
        ("profile_iot_weather", "iot_weather", "IoT / Weather Health", "Basic reachability and data freshness", "network_then_device", "yellow"),
        ("profile_ot_energy", "ot_energy", "OT / Energy Health", "Modbus/502 reachability and future data freshness", "network_then_modbus", "amber"),
    ]

    for profile_id, device_type, profile_name, purpose, polling_method, risk in health_profiles:
        insert_if_missing(
            con,
            "health_profile_template",
            "profile_id",
            profile_id,
            {
                "profile_id": profile_id,
                "device_type": device_type,
                "profile_name": profile_name,
                "purpose": purpose,
                "polling_method": polling_method,
                "risk_level": risk,
                "status": "active",
                "notes": "Seeded v001 profile. Detailed checks added in later phases.",
            },
        )


def record_migration(con) -> None:
    existing = con.execute(
        "SELECT COUNT(*) FROM dgem.schema_migration_log WHERE migration_id = ?",
        [MIGRATION_ID],
    ).fetchone()[0]

    if existing:
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
            "DG-E&M DuckDB foundation evidence/config schema",
            now_iso(),
            "runner/approved_scripts/duckdb_init_schema_v001.py",
            "applied",
            "Created schema, tables, reference seeds, and views.",
        ],
    )


def show_summary(con, db_path: str) -> None:
    tables = con.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'dgem' AND table_type = 'BASE TABLE'
        ORDER BY table_name
    """).fetchall()

    views = con.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'dgem' AND table_type = 'VIEW'
        ORDER BY table_name
    """).fetchall()

    print("")
    print("DG-E&M DuckDB foundation schema v001 complete")
    print(f"Database: {db_path}")
    print(f"Tables:   {len(tables)}")
    print(f"Views:    {len(views)}")
    print("")
    print("Tables:")
    for (name,) in tables:
        print(f"  - dgem.{name}")
    print("")
    print("Views:")
    for (name,) in views:
        print(f"  - dgem.{name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialise DG-E&M DuckDB foundation schema v001")
    parser.add_argument("--db", default=DEFAULT_DB, help="DuckDB path")
    args = parser.parse_args()

    try:
        import duckdb
    except ModuleNotFoundError:
        print("ERROR: Python module 'duckdb' is not installed for host python3.")
        print("Install with: python3 -m pip install --user duckdb")
        return 10

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect(str(db_path))

    create_schema(con)
    seed_reference_data(con)
    create_views(con)
    record_migration(con)
    show_summary(con, str(db_path))

    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
