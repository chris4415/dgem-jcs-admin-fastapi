# DG-E&M Advanced Port Scan Import v001

## Purpose

Import Advanced Port Scanner / Advanced IP Scanner exports into the DG-E&M DuckDB evidence layer.

## Scope

This importer parses scan export files and writes structured discovery evidence to DuckDB.

It populates:

- raw_import_file
- scan_snapshot
- device_observation
- port_observation
- service_observation

## Boundary

This importer does not:

- approve assets
- create final configuration
- start monitoring
- run a live network scan
- classify final device truth
- change security state directly

## Governing Rule

Advanced Port Scanner output is evidence.

Parsed records are structured evidence.

Nothing becomes approved truth until later governed review/rules.

## Supported Inputs v001

- Advanced Port Scanner / Advanced IP Scanner HTML export
- Basic CSV summary import where compatible columns exist

## Runtime Database

data/duckdb/dgem_core.duckdb

## Example

python3 runner/approved_scripts/advanced_port_scan_import_v001.py \
  --db data/duckdb/dgem_core.duckdb \
  --file "data/imports/network_scans/advanced_ip_scan.html" \
  --imported-by chris

## Next Phase

The importer script will be created as:

runner/approved_scripts/advanced_port_scan_import_v001.py

The script imports evidence only. It does not approve assets or start monitoring.
