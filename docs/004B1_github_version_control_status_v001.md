# DG-E&M GitHub Version Control Status v001

## Purpose

Add visible GitHub version-control status and history to the JCS-admin web workflow.

The GitHub page must show that GitHub is the source-code, documentation, tag, rollback, and build-history backup layer.

## Page Location

Set Up -> GitHub

## Initial Visible Fields

- Repository
- Branch
- Remote
- Working tree status
- Latest commit
- Latest tag
- Backup Now future action
- Version-control history

## Boundary

GitHub backs up source code, templates, registries, docs, and Docker build files.

GitHub must not back up secrets, runtime logs, DuckDB runtime files, harvested evidence, or machine credentials.
