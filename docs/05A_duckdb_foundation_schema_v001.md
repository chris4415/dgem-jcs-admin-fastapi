# DG-E&M DuckDB Foundation Schema v001

## Purpose

Create the DG-E&M DuckDB evidence/configuration foundation.

This database stores discovery evidence, candidate assets, approved assets, security watch records, port exposure records, health profiles, and current health state.

## Governing Rule

Raw scan = evidence.

Parsed scan = structured evidence.

Candidate asset = interpreted evidence.

Approved asset = governed configuration.

Health state = evaluated operating state.

Map/dashboard/AI = presentation and explanation layer.

## Database Path

Runtime database:

`data/duckdb/dgem_core.duckdb`

This file is excluded from Git.

## v001 Scope

Creates:

- schema migration log
- evidence source register
- raw import file register
- scan snapshot register
- device observation table
- port observation table
- service observation table
- candidate asset register
- approved asset register
- asset interface register
- VLAN register
- zone register
- policy matrix
- port exposure register
- risk finding register
- security watch register
- security watch scan schedule
- health profile template register
- health check definition table
- health check instance table
- health metric observation table
- health state current table
- health state history table

## Security Principle

Every discovered device is stored.

Selected devices go to onboarding.

Unselected devices go to security watch.

Nothing becomes approved truth without governed review/rules.
