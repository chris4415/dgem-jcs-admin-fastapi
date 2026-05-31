#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

DEFAULT_DB = "data/duckdb/dgem_core.duckdb"
MIGRATION_ID = "05C_candidate_asset_rationalisation_v001"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def make_id(prefix: str, *parts) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return f"{prefix}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def norm(value: str) -> str:
    return (value or "").strip()


def norm_lower(value: str) -> str:
    return norm(value).lower()


def normalise_mac(mac: str) -> str:
    mac = norm_lower(mac)
    mac = re.sub(r"[^0-9a-f]", "", mac)
    if len(mac) == 12:
        return ":".join(mac[i:i+2] for i in range(0, 12, 2))
    return mac


def is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", norm(value)))


def evidence_group_key(device: Dict) -> str:
    mac = normalise_mac(device.get("mac_address", ""))
    hostname = norm_lower(device.get("hostname", ""))
    ip = norm(device.get("ip_address", ""))

    # DG-E&M rule:
    # IP address is an observation, not the asset.
    # Prefer stable non-IP hostnames so multi-interface devices collapse
    # into one candidate asset for review, while every observed IP/MAC
    # remains stored as scan evidence in DuckDB.
    if hostname and not is_ip(hostname):
        return f"host:{hostname}"
    if mac:
        return f"mac:{mac}"
    return f"ip:{ip}"



def looks_like_nas_model_name(hostname: str) -> bool:
    h = re.sub(r"[^a-z0-9+]", "", norm_lower(hostname))

    # Synology-style model names seen in this environment:
    # DS1621Plus, DS1621+, RS815, RS815-PLEX, RS815-SURVAIL.
    if h.startswith(("ds", "rs")) and any(ch.isdigit() for ch in h[2:7]):
        return True

    return False


def classify_device(manufacturer: str, hostname: str, ports: List[int], service_text: str) -> Tuple[str, float, str]:
    m = norm_lower(manufacturer)
    h = norm_lower(hostname)
    s = norm_lower(service_text)
    p = set(ports)

    reasons = []

    # NAS model-name shortcut.
    # Catches Synology-style hostnames such as DS1621Plus, DS1621+, RS815, RS815-PLEX.
    if looks_like_nas_model_name(hostname):
        reasons.append("NAS model-name evidence detected")
        return "nas", 0.92, "; ".join(reasons)

    if (
        "synology" in m
        or "synology" in h
        or "qnap" in m
        or "qnap" in h
        or re.search(r"\\b(ds|rs)\\d{3,5}(plus|xs|rp|\\+)?\\b", h)
        or 5000 in p
        or 5001 in p
    ):
        reasons.append("NAS/Synology/QNAP model evidence or DSM ports detected")
        return "nas", 0.92, "; ".join(reasons)

    if "esxi" in h or 902 in p or 912 in p:
        reasons.append("VMware/ESXi management ports or ESXi naming detected")
        return "vmware_esxi", 0.90, "; ".join(reasons)

    if "fronius" in m or "fronius" in h or 502 in p:
        reasons.append("Fronius/Modbus OT evidence detected")
        return "ot_energy", 0.90, "; ".join(reasons)

    if 554 in p or "rtsp" in s or "hikvision" in m or "dahua" in m or "camera" in h:
        reasons.append("RTSP/camera evidence detected")
        return "security_camera", 0.86, "; ".join(reasons)

    if 9100 in p or 631 in p or 515 in p or "printer" in h or "brother" in m or "canon" in m or "epson" in m or "hewlett" in m or "hp " in m:
        reasons.append("Printer service or printer manufacturer evidence detected")
        return "printer", 0.84, "; ".join(reasons)

    if "procurve" in m or "switch" in h or "aruba" in m:
        reasons.append("Switch/vendor evidence detected")
        return "switch", 0.84, "; ".join(reasons)

    if "asus" in m or "router" in h or "gateway" in h or (53 in p and (80 in p or 443 in p)):
        reasons.append("Router/gateway/DNS/web management evidence detected")
        return "router_gateway", 0.82, "; ".join(reasons)

    if 3389 in p or 135 in p or 139 in p or 445 in p or "microsoft" in m or "windows" in s or "iis" in s:
        reasons.append("Windows/RDP/SMB/RPC evidence detected")
        return "windows_host", 0.80, "; ".join(reasons)

    if "vmware" in m:
        reasons.append("VMware manufacturer evidence without ESXi management ports; likely virtual machine guest")
        return "virtual_machine_guest", 0.70, "; ".join(reasons)

    if "samsung" in m or "lg " in m or "android" in s or "tv" in h:
        reasons.append("Smart TV/media manufacturer or naming evidence detected")
        return "smart_tv_media", 0.72, "; ".join(reasons)

    if "acurite" in m or "weather" in h or "simplelink" in m or "espressif" in m or "iot" in h:
        reasons.append("IoT/weather manufacturer or naming evidence detected")
        return "iot_weather", 0.72, "; ".join(reasons)

    if 22 in p:
        reasons.append("SSH detected without stronger classification")
        return "linux_or_network_host", 0.62, "; ".join(reasons)

    if 80 in p or 443 in p or 8080 in p or 8090 in p or 8443 in p:
        reasons.append("Web-managed device detected without stronger classification")
        return "web_managed_appliance", 0.58, "; ".join(reasons)

    reasons.append("Insufficient evidence for strong classification")
    return "unknown", 0.35, "; ".join(reasons)


def risk_level_from_ports(ports: List[int]) -> str:
    p = set(ports)

    if 23 in p or 3389 in p:
        return "red"

    if p.intersection({21, 135, 139, 445, 502, 554, 623, 902, 912, 5000, 5001}):
        return "amber"

    if p.intersection({80, 443, 8080, 8090, 8443, 22}):
        return "yellow"

    return "green"


def add_columns_if_missing(con) -> None:
    desired = {
        "discovery_mode": "VARCHAR",
        "baseline_status": "VARCHAR",
        "source_scan_id": "VARCHAR",
        "primary_ip": "VARCHAR",
        "primary_mac": "VARCHAR",
        "port_summary": "VARCHAR",
        "service_summary": "VARCHAR",
        "classification_reason": "VARCHAR",
    }

    existing = {
        row[0]
        for row in con.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'dgem'
              AND table_name = 'candidate_asset'
        """).fetchall()
    }

    for col, col_type in desired.items():
        if col not in existing:
            con.execute(f"ALTER TABLE dgem.candidate_asset ADD COLUMN {col} {col_type}")


def create_views(con) -> None:
    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_candidate_asset_detail AS
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
        discovery_mode,
        baseline_status,
        source_scan_id,
        primary_ip,
        primary_mac,
        port_summary,
        service_summary,
        classification_reason,
        first_seen,
        last_seen,
        notes
    FROM dgem.candidate_asset
    """)

    con.execute("""
    CREATE OR REPLACE VIEW dgem.vw_candidate_asset_review_queue AS
    SELECT
        candidate_asset_id,
        likely_hostname,
        likely_device_type,
        likely_manufacturer,
        primary_ip,
        primary_mac,
        port_summary,
        risk_level,
        confidence_score,
        managed_status,
        review_status,
        security_watch,
        baseline_status,
        classification_reason
    FROM dgem.candidate_asset
    WHERE COALESCE(review_status, '') <> 'approved'
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
    """)


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
            "Candidate asset rationalisation from discovery evidence",
            now_iso(),
            "runner/approved_scripts/candidate_asset_rationalisation_v001.py",
            "applied",
            "Added candidate_asset support columns and candidate review views.",
        ],
    )


def latest_scan_id(con) -> str:
    row = con.execute("""
        SELECT scan_id
        FROM dgem.scan_snapshot
        ORDER BY imported_at DESC
        LIMIT 1
    """).fetchone()

    return row[0] if row else ""


def rows_as_dicts(con, sql: str, params=None) -> List[Dict]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def build_candidates(con, scan_id: str, discovery_mode: str) -> List[Dict]:
    devices = rows_as_dicts(
        con,
        """
        SELECT *
        FROM dgem.device_observation
        WHERE scan_id = ?
        ORDER BY ip_address
        """,
        [scan_id],
    )

    if not devices:
        return []

    ports = rows_as_dicts(
        con,
        """
        SELECT ip_address, mac_address, port, protocol, service_name, service_detail, risk_hint
        FROM dgem.port_observation
        WHERE scan_id = ?
        ORDER BY ip_address, port
        """,
        [scan_id],
    )

    services = rows_as_dicts(
        con,
        """
        SELECT ip_address, mac_address, service_type, service_url, banner, shared_resource, notes
        FROM dgem.service_observation
        WHERE scan_id = ?
        ORDER BY ip_address, service_type
        """,
        [scan_id],
    )

    port_by_ip = defaultdict(list)
    port_by_mac = defaultdict(list)
    for p in ports:
        port_by_ip[norm(p.get("ip_address"))].append(p)
        mac = normalise_mac(p.get("mac_address", ""))
        if mac:
            port_by_mac[mac].append(p)

    svc_by_ip = defaultdict(list)
    svc_by_mac = defaultdict(list)
    for s in services:
        svc_by_ip[norm(s.get("ip_address"))].append(s)
        mac = normalise_mac(s.get("mac_address", ""))
        if mac:
            svc_by_mac[mac].append(s)

    groups = defaultdict(list)
    for d in devices:
        groups[evidence_group_key(d)].append(d)

    candidates = []

    for group_key, group_devices in groups.items():
        group_devices = sorted(group_devices, key=lambda d: norm(d.get("ip_address")))

        primary = group_devices[0]
        primary_ip = norm(primary.get("ip_address"))
        primary_mac = normalise_mac(primary.get("mac_address", ""))

        all_ips = sorted({norm(d.get("ip_address")) for d in group_devices if norm(d.get("ip_address"))})
        all_macs = sorted({normalise_mac(d.get("mac_address", "")) for d in group_devices if normalise_mac(d.get("mac_address", ""))})
        hostnames = [norm(d.get("hostname")) for d in group_devices if norm(d.get("hostname"))]
        manufacturers = [norm(d.get("manufacturer")) for d in group_devices if norm(d.get("manufacturer"))]

        likely_hostname = hostnames[0] if hostnames else primary_ip
        likely_manufacturer = manufacturers[0] if manufacturers else ""

        related_ports = []
        related_services = []

        for ip in all_ips:
            related_ports.extend(port_by_ip[ip])
            related_services.extend(svc_by_ip[ip])

        for mac in all_macs:
            related_ports.extend(port_by_mac[mac])
            related_services.extend(svc_by_mac[mac])

        # De-duplicate port/service evidence.
        port_seen = set()
        unique_ports = []
        for p in related_ports:
            key = (p.get("ip_address"), p.get("port"), p.get("protocol"))
            if key not in port_seen:
                port_seen.add(key)
                unique_ports.append(p)

        svc_seen = set()
        unique_services = []
        for s in related_services:
            key = (s.get("ip_address"), s.get("service_type"), s.get("banner"), s.get("shared_resource"))
            if key not in svc_seen:
                svc_seen.add(key)
                unique_services.append(s)

        port_numbers = sorted({int(p.get("port")) for p in unique_ports if p.get("port") is not None})
        port_summary = ", ".join(str(p) for p in port_numbers)

        service_parts = []
        for s in unique_services[:20]:
            piece = norm(s.get("service_type"))
            banner = norm(s.get("banner"))
            shared = norm(s.get("shared_resource"))
            if shared:
                piece = f"{piece}:{shared}"
            elif banner:
                piece = f"{piece}:{banner[:80]}"
            if piece:
                service_parts.append(piece)

        service_summary = "; ".join(service_parts)

        likely_type, confidence, reason = classify_device(
            likely_manufacturer,
            likely_hostname,
            port_numbers,
            service_summary,
        )

        risk_level = risk_level_from_ports(port_numbers)

        existing_count = con.execute(
            "SELECT COUNT(*) FROM dgem.candidate_asset WHERE evidence_group_key = ?",
            [group_key],
        ).fetchone()[0]

        if existing_count:
            baseline_status = "existing_candidate"
        elif discovery_mode == "equipment_addition":
            baseline_status = "new_equipment_candidate"
        else:
            baseline_status = "new_baseline_candidate"

        notes = {
            "mode": discovery_mode,
            "all_ips": all_ips,
            "all_macs": all_macs,
            "evidence_counts": {
                "device_observations": len(group_devices),
                "port_observations": len(unique_ports),
                "service_observations": len(unique_services),
            },
            "rule": "IP address is observation, not asset identity.",
        }

        candidate_id = make_id("cand", group_key)

        candidates.append({
            "candidate_asset_id": candidate_id,
            "evidence_group_key": group_key,
            "likely_hostname": likely_hostname,
            "likely_device_type": likely_type,
            "likely_manufacturer": likely_manufacturer,
            "confidence_score": confidence,
            "managed_status": "unmanaged_security_watch",
            "review_status": "pending_review",
            "selected_for_onboarding": False,
            "security_watch": True,
            "risk_level": risk_level,
            "first_seen": now_iso(),
            "last_seen": now_iso(),
            "notes": json.dumps(notes, sort_keys=True),
            "discovery_mode": discovery_mode,
            "baseline_status": baseline_status,
            "source_scan_id": scan_id,
            "primary_ip": primary_ip,
            "primary_mac": primary_mac,
            "port_summary": port_summary,
            "service_summary": service_summary,
            "classification_reason": reason,
        })

    return candidates


def upsert_candidate(con, row: Dict) -> str:
    exists = con.execute(
        "SELECT COUNT(*) FROM dgem.candidate_asset WHERE candidate_asset_id = ?",
        [row["candidate_asset_id"]],
    ).fetchone()[0]

    if exists:
        con.execute(
            """
            UPDATE dgem.candidate_asset
            SET
                likely_hostname = ?,
                likely_device_type = ?,
                likely_manufacturer = ?,
                confidence_score = ?,
                risk_level = ?,
                last_seen = ?,
                notes = ?,
                discovery_mode = ?,
                baseline_status = ?,
                source_scan_id = ?,
                primary_ip = ?,
                primary_mac = ?,
                port_summary = ?,
                service_summary = ?,
                classification_reason = ?
            WHERE candidate_asset_id = ?
            """,
            [
                row["likely_hostname"],
                row["likely_device_type"],
                row["likely_manufacturer"],
                row["confidence_score"],
                row["risk_level"],
                row["last_seen"],
                row["notes"],
                row["discovery_mode"],
                row["baseline_status"],
                row["source_scan_id"],
                row["primary_ip"],
                row["primary_mac"],
                row["port_summary"],
                row["service_summary"],
                row["classification_reason"],
                row["candidate_asset_id"],
            ],
        )
        return "updated"

    cols = list(row.keys())
    con.execute(
        f"INSERT INTO dgem.candidate_asset ({', '.join(cols)}) VALUES ({', '.join(['?'] * len(cols))})",
        [row[c] for c in cols],
    )
    return "inserted"


def show_summary(con, inserted: int, updated: int) -> None:
    print("")
    print("DG-E&M Candidate Asset Rationalisation v001 complete")
    print(f"Inserted candidates: {inserted}")
    print(f"Updated candidates:  {updated}")

    print("")
    print("Candidate counts by type/risk:")
    for row in con.execute("""
        SELECT likely_device_type, risk_level, COUNT(*) AS count
        FROM dgem.candidate_asset
        GROUP BY likely_device_type, risk_level
        ORDER BY count DESC, likely_device_type, risk_level
    """).fetchall():
        print(row)

    print("")
    print("Review queue sample:")
    for row in con.execute("""
        SELECT likely_hostname, likely_device_type, primary_ip, primary_mac, port_summary, risk_level, confidence_score
        FROM dgem.vw_candidate_asset_review_queue
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
        LIMIT 25
    """).fetchall():
        print(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Rationalise DG-E&M discovery evidence into candidate assets")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--scan-id", default="")
    parser.add_argument(
        "--mode",
        default="initial_baseline",
        choices=["initial_baseline", "equipment_addition", "periodic_rescan", "security_watch_rescan"],
    )
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

    add_columns_if_missing(con)
    create_views(con)
    record_migration(con)

    scan_id = args.scan_id or latest_scan_id(con)
    if not scan_id:
        print("ERROR: No scan_snapshot exists. Import scan evidence first.", file=sys.stderr)
        return 2

    candidates = build_candidates(con, scan_id, args.mode)
    if not candidates:
        print(f"ERROR: No device observations found for scan_id={scan_id}", file=sys.stderr)
        return 2

    inserted = 0
    updated = 0

    for row in candidates:
        result = upsert_candidate(con, row)
        if result == "inserted":
            inserted += 1
        else:
            updated += 1

    show_summary(con, inserted, updated)

    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
