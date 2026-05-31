# DG-E&M API-widget Results Review Page v001

## Purpose

Expose API-widget packets, constrained API analysis results, and recommended governed action IDs in the JCS-admin website.

## Route

/ai/api-widget-results

## Boundary

This page is read-only.

It does not:

- call the OpenAI API
- approve assets
- execute actions
- change candidate status
- change switch/router/firewall configuration
- start monitoring
- create alarms

## Source Tables

- dgem.api_analysis_packet
- dgem.api_analysis_result
- dgem.api_widget_recommendation
- dgem.candidate_asset

## v001 Behaviour

Shows:

- packet status
- candidate hostname/type/risk
- API result severity
- API summary
- recommended action IDs
- approval requirement
- recommendation status

## Governing Rule

API-widget output is advisory analysis evidence.

Recommended action IDs remain recommendations only until a future governed approval/action workflow executes them.
