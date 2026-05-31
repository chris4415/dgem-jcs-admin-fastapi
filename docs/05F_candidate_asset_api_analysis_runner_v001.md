# DG-E&M Candidate Asset API Analysis Runner v001

## Purpose

Run constrained API analysis for candidate asset API-widget packets.

This phase takes one or more packets from `dgem.api_analysis_packet`, sends the bounded facts/rules/actions context to the OpenAI API, and stores the structured analysis result in DuckDB.

## Boundary

This phase does not:

- approve assets
- write final truth
- execute commands
- change switch/router/firewall configuration
- disable ports
- move VLANs
- start monitoring
- create process/security alarms

## Governing Rule

The API analyses bounded DG-E&M facts.

The API result is advisory analysis evidence.

The API result may recommend registered action IDs only.

All recommended actions still require governed approval and runner execution.

## Source Tables

- dgem.api_analysis_packet
- dgem.api_widget_registry

## Target Tables

- dgem.api_analysis_result
- dgem.api_widget_recommendation
- dgem.api_analysis_packet status update

## Required Environment

OPENAI_API_KEY must be present in the runtime environment.

Optional:

DGEM_OPENAI_MODEL can override the default model.

## v001 Safety Controls

- one packet by default
- dry-run mode available
- API key is never printed
- packet facts/rules/actions are read from DuckDB
- recommendations are filtered against allowed action IDs
- forbidden actions remain embedded in the packet
- API response is stored for audit

## v001 Tested Model

The first successful v001 API analysis run used:

`gpt-4.1-mini`

The model may be overridden with `DGEM_OPENAI_MODEL`.
