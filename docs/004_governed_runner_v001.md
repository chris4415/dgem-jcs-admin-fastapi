# DG-E&M Governed Runner v001

## Purpose

Create the controlled execution boundary for JCS-admin.

The web interface and ChatGPT API integration must not directly execute scripts, shell commands, filesystem changes, or unmanaged actions.

All executable actions must pass through a governed runner model.

## Core rule

The website requests an action.
The API/control layer validates the action.
The runner executes only registered approved actions.
The result is logged and auditable.

## Initial goals

1. Define an action registry.
2. Define a script registry.
3. Allow only registry-approved action IDs.
4. Reject arbitrary script paths.
5. Generate a run ID for every execution.
6. Capture start time, end time, actor, command, status, return code, stdout, stderr, and timeout.
7. Write runner audit records to JSONL.
8. Prepare for future DuckDB mirror tables.
9. Keep runner execution separate from AI reasoning.

## Initial protected route

- /runner/test

This route must require login.

## Initial approved action

- action_id: runner_echo_test_v001
- purpose: prove governed runner path
- command: echo controlled runner test
- risk: low
- stage: development only

## Required audit fields

- run_id
- action_id
- actor
- role
- requested_at
- started_at
- finished_at
- status
- return_code
- stdout
- stderr
- duration_ms
- timeout_seconds

## Boundary rules

The runner must not:

- accept arbitrary command text from the browser
- accept arbitrary filesystem paths from the API
- run unregistered scripts
- run without authenticated actor identity
- run without an audit record
- hide failures

## Future versions

Future versions should add:

- DuckDB runner audit mirror
- queue table
- action approval workflow
- per-action permissions
- timeout policy registry
- script hash/version checks
- lifecycle-stage checks
- role-based execution permissions
