#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_DB = "data/duckdb/dgem_core.duckdb"
SOURCE_ID = "advanced_port_scanner_import"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def make_id(prefix: str, *parts) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return f"{prefix}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def clean_text(value: str) -> str:
    value = html.unescape(value or "")
    value = re.sub(r"<[^>]+>", " ", value)
    value = value.replace("\u200e", "")
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def service_from_port(port: int) -> str:
    names = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS RPC",
        139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
        427: "SLP", 443: "HTTPS", 445: "SMB", 502: "Modbus/TCP",
        515: "LPD Print", 548: "AFP", 554: "RTSP", 623: "IPMI",
        631: "IPP Print", 873: "rsync", 902: "VMware", 912: "VMware",
        993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 1883: "MQTT",
        3306: "MySQL", 3389: "RDP", 5000: "Synology DSM HTTP",
        5001: "Synology DSM HTTPS", 5432: "PostgreSQL", 5900: "VNC",
        8000: "Web App", 8080: "Web Admin", 8090: "Web Admin",
        8443: "Alt HTTPS", 8883: "MQTT TLS", 9000: "Web Service",
        9100: "JetDirect Print",
    }
    return names.get(port, f"TCP/{port}")


def risk_hint_for_port(port: int) -> str:
    if port == 23:
        return "high: telnet/insecure management"
    if port == 21:
        return "amber: ftp exposure"
    if port in (135, 139, 445):
        return "amber: windows/smb/rpc exposure"
    if port == 3389:
        return "high: rdp management exposure"
    if port == 502:
        return "amber: modbus/ot exposure"
    if port == 554:
        return "amber: rtsp/camera exposure"
    if port in (5000, 5001):
        return "amber: synology management exposure"
    if port in (902, 912):
        return "amber: vmware management exposure"
    if port in (80, 443, 8080, 8090, 8443):
        return "info: web/admin surface"
    return ""


def parse_port_text(value: str) -> Optional[Dict]:
    text = clean_text(value)
    m = re.search(r"(\d+)\s*\((TCP|UDP)\)", text, flags=re.I)
    if not m:
        return None
    port = int(m.group(1))
    proto = m.group(2).upper()
    return {
        "port": port,
        "protocol": proto,
        "service_name": service_from_port(port),
        "service_detail": text,
        "observed_state": "open",
        "risk_hint": risk_hint_for_port(port),
    }


def extract_divs(row_html: str, class_name: str) -> List[str]:
    pattern = rf"<div\b[^>]*class=[\"'][^\"']*\b{class_name}\b[^\"']*[\"'][^>]*>(.*?)</div>"
    return [clean_text(x) for x in re.findall(pattern, row_html, flags=re.I | re.S)]


def extract_href(row_html: str) -> str:
    m = re.search(r"<a\b[^>]*href=[\"']([^\"']+)[\"']", row_html, flags=re.I | re.S)
    return html.unescape(m.group(1)) if m else ""


def parse_html_export(path: Path) -> Dict[str, List[Dict]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = re.findall(r"<tr\b[^>]*>(.*?)</tr>", text, flags=re.I | re.S)

    devices: List[Dict] = []
    ports: List[Dict] = []
    services: List[Dict] = []
    current = None

    for idx, row in enumerate(rows):
        head_cells = re.findall(
            r"<td\b[^>]*class=[\"'][^\"']*\bhead\b[^\"']*[\"'][^>]*>(.*?)</td>",
            row,
            flags=re.I | re.S,
        )
        head_cells = [clean_text(c) for c in head_cells]

        if len(head_cells) >= 6:
            status, name, ip, manufacturer, mac, comments = head_cells[:6]
            if ip.lower() == "ip":
                current = None
                continue
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                current = {
                    "row_index": idx,
                    "status": status,
                    "hostname": name,
                    "ip_address": ip,
                    "manufacturer": manufacturer,
                    "mac_address": mac,
                    "comments": comments,
                }
                devices.append(current)
            else:
                current = None
            continue

        if not current:
            continue

        labels = extract_divs(row, "rhead")
        results = extract_divs(row, "res")
        href = extract_href(row)

        if not labels:
            continue

        label = labels[0].rstrip(":").strip()
        label_lower = label.lower()

        if label_lower == "ports":
            for result in results:
                parsed = parse_port_text(result)
                if parsed:
                    parsed["ip_address"] = current["ip_address"]
                    parsed["mac_address"] = current["mac_address"]
                    ports.append(parsed)
            continue

        if not results:
            services.append({
                "ip_address": current["ip_address"],
                "mac_address": current["mac_address"],
                "service_type": label,
                "service_url": href,
                "banner": "",
                "shared_resource": "",
                "notes": "No detail values in export row.",
            })
            continue

        for result in results:
            if label_lower == "shared folders":
                services.append({
                    "ip_address": current["ip_address"],
                    "mac_address": current["mac_address"],
                    "service_type": "shared_folder",
                    "service_url": "",
                    "banner": "",
                    "shared_resource": result,
                    "notes": label,
                })
            else:
                services.append({
                    "ip_address": current["ip_address"],
                    "mac_address": current["mac_address"],
                    "service_type": label,
                    "service_url": href,
                    "banner": result,
                    "shared_resource": "",
                    "notes": label,
                })

    return {"devices": devices, "ports": ports, "services": services}


def parse_csv_export(path: Path) -> Dict[str, List[Dict]]:
    devices: List[Dict] = []
    ports: List[Dict] = []

    def norm(k: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", (k or "").strip().lower()).strip("_")

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for idx, raw in enumerate(reader):
            row = {norm(k): (v or "").strip() for k, v in raw.items()}
            ip = row.get("ip") or row.get("ip_address") or row.get("address") or ""
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                continue

            mac = row.get("mac_address") or row.get("mac") or ""
            devices.append({
                "row_index": idx,
                "status": row.get("status", ""),
                "hostname": row.get("name") or row.get("hostname") or ip,
                "ip_address": ip,
                "manufacturer": row.get("manufacturer", ""),
                "mac_address": mac,
                "comments": row.get("comments", ""),
            })

            for part in re.split(r"[;,]", row.get("ports") or row.get("open_ports") or ""):
                part = part.strip()
                parsed = parse_port_text(part)
                if not parsed and part.isdigit():
                    port = int(part)
                    parsed = {
                        "port": port,
                        "protocol": "TCP",
                        "service_name": service_from_port(port),
                        "service_detail": part,
                        "observed_state": "open",
                        "risk_hint": risk_hint_for_port(port),
                    }
                if parsed:
                    parsed["ip_address"] = ip
                    parsed["mac_address"] = mac
                    ports.append(parsed)

    return {"devices": devices, "ports": ports, "services": []}


def parse_export(path: Path) -> Dict[str, List[Dict]]:
    suffix = path.suffix.lower()
    if suffix in (".html", ".htm"):
        return parse_html_export(path)
    if suffix == ".csv":
        return parse_csv_export(path)
    raise ValueError(f"Unsupported file type: {suffix}")


def insert_if_missing(con, table: str, key_col: str, key_val: str, row: Dict) -> int:
    found = con.execute(f"SELECT COUNT(*) FROM dgem.{table} WHERE {key_col} = ?", [key_val]).fetchone()[0]
    if found:
        return 0

    cols = list(row.keys())
    sql = f"INSERT INTO dgem.{table} ({', '.join(cols)}) VALUES ({', '.join(['?'] * len(cols))})"
    con.execute(sql, [row[c] for c in cols])
    return 1


def import_to_duckdb(con, file_path: Path, imported_by: str, parsed: Dict, file_hash: str) -> Dict[str, int]:
    ts = now_iso()
    file_id = make_id("file", file_hash)
    scan_id = make_id("scan", file_hash)

    counts = {
        "raw_import_file": 0,
        "scan_snapshot": 0,
        "device_observation": 0,
        "port_observation": 0,
        "service_observation": 0,
    }

    counts["raw_import_file"] += insert_if_missing(con, "raw_import_file", "file_id", file_id, {
        "file_id": file_id,
        "source_id": SOURCE_ID,
        "file_path": str(file_path),
        "file_name": file_path.name,
        "file_type": file_path.suffix.lower().lstrip("."),
        "file_hash": file_hash,
        "imported_at": ts,
        "imported_by": imported_by,
        "parse_status": "parsed",
        "notes": "Imported by advanced_port_scan_import_v001.",
    })

    record_count = len(parsed["devices"]) + len(parsed["ports"]) + len(parsed["services"])

    counts["scan_snapshot"] += insert_if_missing(con, "scan_snapshot", "scan_id", scan_id, {
        "scan_id": scan_id,
        "source_id": SOURCE_ID,
        "file_id": file_id,
        "scan_type": "advanced_port_scanner_import",
        "scan_scope": "from_export_file",
        "scan_started_at": None,
        "scan_finished_at": None,
        "imported_at": ts,
        "imported_by": imported_by,
        "record_count": record_count,
        "evidence_quality": "imported_external_scan",
        "status": "imported",
        "notes": "External scan output imported as evidence only.",
    })

    for idx, d in enumerate(parsed["devices"]):
        oid = make_id("devobs", scan_id, idx, d.get("ip_address"), d.get("mac_address"), d.get("hostname"))
        counts["device_observation"] += insert_if_missing(con, "device_observation", "observation_id", oid, {
            "observation_id": oid,
            "scan_id": scan_id,
            "observed_at": ts,
            "ip_address": d.get("ip_address", ""),
            "hostname": d.get("hostname", ""),
            "mac_address": d.get("mac_address", ""),
            "manufacturer": d.get("manufacturer", ""),
            "status": d.get("status", ""),
            "vlan_id": "",
            "zone_id": "",
            "device_label": d.get("hostname", "") or d.get("ip_address", ""),
            "evidence_text": d.get("comments", ""),
        })

    for idx, p in enumerate(parsed["ports"]):
        pid = make_id("portobs", scan_id, idx, p.get("ip_address"), p.get("mac_address"), p.get("port"), p.get("protocol"))
        counts["port_observation"] += insert_if_missing(con, "port_observation", "port_observation_id", pid, {
            "port_observation_id": pid,
            "scan_id": scan_id,
            "observed_at": ts,
            "ip_address": p.get("ip_address", ""),
            "mac_address": p.get("mac_address", ""),
            "port": int(p.get("port", 0)),
            "protocol": p.get("protocol", "TCP"),
            "service_name": p.get("service_name", ""),
            "service_detail": p.get("service_detail", ""),
            "observed_state": p.get("observed_state", "open"),
            "risk_hint": p.get("risk_hint", ""),
        })

    for idx, s in enumerate(parsed["services"]):
        sid = make_id("svcobs", scan_id, idx, s.get("ip_address"), s.get("service_type"), s.get("banner"), s.get("shared_resource"))
        counts["service_observation"] += insert_if_missing(con, "service_observation", "service_observation_id", sid, {
            "service_observation_id": sid,
            "scan_id": scan_id,
            "observed_at": ts,
            "ip_address": s.get("ip_address", ""),
            "mac_address": s.get("mac_address", ""),
            "service_type": s.get("service_type", ""),
            "service_url": s.get("service_url", ""),
            "banner": s.get("banner", ""),
            "shared_resource": s.get("shared_resource", ""),
            "notes": s.get("notes", ""),
        })

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Advanced Port Scanner exports into DG-E&M DuckDB")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--file", required=True)
    parser.add_argument("--imported-by", default="unknown")
    args = parser.parse_args()

    try:
        import duckdb
    except ModuleNotFoundError:
        print("ERROR: Python module duckdb is not installed.", file=sys.stderr)
        return 10

    db_path = Path(args.db)
    file_path = Path(args.file)

    if not db_path.exists():
        print(f"ERROR: DuckDB file not found: {db_path}", file=sys.stderr)
        return 2

    if not file_path.exists():
        print(f"ERROR: Import file not found: {file_path}", file=sys.stderr)
        return 2

    parsed = parse_export(file_path)
    file_hash = sha256_file(file_path)

    con = duckdb.connect(str(db_path))
    counts = import_to_duckdb(con, file_path, args.imported_by, parsed, file_hash)

    print("")
    print("DG-E&M Advanced Port Scan import v001 complete")
    print(f"File: {file_path}")
    print(f"Devices parsed:  {len(parsed['devices'])}")
    print(f"Ports parsed:    {len(parsed['ports'])}")
    print(f"Services parsed: {len(parsed['services'])}")
    print("")
    print("Inserted this run:")
    for k, v in counts.items():
        print(f"  - {k}: {v}")

    print("")
    print("Top open-port evidence:")
    rows = con.execute("""
        SELECT port, protocol, service_name, COUNT(*) AS count
        FROM dgem.port_observation
        GROUP BY port, protocol, service_name
        ORDER BY count DESC, port
        LIMIT 20
    """).fetchall()
    for port, proto, service, count in rows:
        print(f"  - {port}/{proto} {service}: {count}")

    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
