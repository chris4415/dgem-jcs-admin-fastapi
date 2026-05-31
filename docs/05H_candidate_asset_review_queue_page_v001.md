# DG-E&M Candidate Asset Review Queue Page v001

## Purpose

Expose candidate assets from DuckDB in a read-only website review queue.

This page supports Establish-stage review of discovered network assets before anything is approved, onboarded, monitored, or acted on.

## Route

/dashboards/candidate-assets

## Boundary

This page is read-only.

It does not:

- approve assets
- change review status
- execute actions
- call the OpenAI API
- change switch/router/firewall configuration
- start monitoring
- create alarms

## Source Tables

- dgem.candidate_asset
- dgem.api_analysis_packet
- dgem.api_analysis_result
- dgem.api_widget_recommendation

## v001 Behaviour

Shows:

- candidate hostname
- likely device type
- primary IP/MAC
- open ports
- risk level
- security-watch status
- review status
- onboarding selected flag
- API-widget result summary where available
- recommendation count

## Governing Rule

Candidate assets are interpreted evidence, not approved truth.

All candidates remain pending review until a future governed approval/onboarding workflow is implemented.
