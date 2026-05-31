# DG-E&M Candidate Asset API Packet Builder v001

## Purpose

Create constrained API-widget analysis packets from candidate asset records.

This phase converts candidate asset evidence into bounded API analysis packets.

## Boundary

This phase does not:

- call the ChatGPT API
- approve assets
- create final truth
- execute actions
- change switch/router/firewall configuration
- start monitoring
- create alarms

## Governing Rule

Facts come from DuckDB.

API packets contain bounded facts, deterministic rule context, allowed outputs, and forbidden actions.

The API may later analyse the packet, but it must not create truth or execute actions.

## Source Tables

- dgem.candidate_asset
- dgem.device_observation
- dgem.port_observation
- dgem.service_observation
- dgem.api_widget_registry

## Target Table

- dgem.api_analysis_packet

## Widget Used

candidate_asset_api_widget_v001

## v001 Behaviour

Build packets for candidate assets that are pending review.

Default packet selection prioritises:

- red risk
- amber risk
- yellow risk
- unknown classification
- security watch candidates

## Future Use

Later phases will send these packets to the constrained API analysis runner.
