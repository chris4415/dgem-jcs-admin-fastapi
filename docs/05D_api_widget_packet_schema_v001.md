# DG-E&M API-widget Packet Schema v001

## Purpose

Create the DuckDB schema foundation for DG-E&M API-widgets.

API-widgets are constrained state-analysis components that use bounded DG-E&M fact packets to request structured analysis from the ChatGPT API.

## Governing Rule

Facts and evidence live in DuckDB.

Deterministic rules create state/findings.

API-widgets analyse bounded context packets.

API-widgets do not approve assets, create final truth, execute actions, or bypass the governed runner.

## API-widget Meaning

An API-widget is not a free chat box.

It is a governed analysis component that:

- reads DG-E&M facts
- builds a constrained packet
- defines allowed outputs
- defines forbidden actions
- sends bounded context to the API in later phases
- stores the structured result
- returns recommendations only

## v001 Scope

This phase creates tables for:

- API-widget registry
- API analysis packets
- API analysis results
- API-widget recommendations
- scheduled API-widget jobs
- scheduled API-widget runs

## Initial API-widget Types

- candidate_asset_analysis
- new_connection_analysis
- network_stress_analysis
- unknown_anomaly_analysis
- port_exposure_analysis
- switch_performance_analysis
- network_optimisation_analysis

## Boundary

This phase does not:

- call the OpenAI API
- execute actions
- approve devices
- change switch/router/firewall config
- create alarms
- start scheduled jobs

## Future Use

Later phases will use these tables to support:

- candidate asset explanation
- network stress and performance analysis
- unknown anomaly analysis
- new connection onboarding recommendations
- port exposure risk explanation
- scheduled constrained analysis jobs
