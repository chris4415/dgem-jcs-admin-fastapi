# DG-E&M Candidate Asset Rationalisation v001

## Purpose

Convert raw network discovery observations into candidate network assets.

This phase reduces IP-address clutter by grouping evidence using:

- MAC address
- hostname
- IP address
- manufacturer
- observed ports
- observed services
- scan history

## Operating Modes

### initial_baseline

Used during first DG-E&M setup.

All discovered devices are recorded as candidate assets.
By default they are marked for security watch until reviewed.

### equipment_addition

Used when new equipment is added later.

New evidence is compared against the existing baseline to identify:

- new asset
- known existing asset
- changed asset
- possible duplicate
- moved IP/MAC
- unmanaged security-watch item

## Boundary

This script does not:

- approve assets
- create final asset_register records
- start monitoring
- run a network scan
- modify devices
- create alarms

## Governing Rule

IP address is not the asset.

IP address is an observation attached to an asset/interface at a point in time.

Every discovered device becomes either:

- onboarding candidate
- unmanaged security-watch candidate
- later approved asset

Nothing becomes approved truth without governed review/rules.

## v001 Rationalisation Notes

Stable hostnames are preferred over MAC addresses where the hostname is not an IP address. This helps collapse multi-interface appliances such as NAS devices into one candidate asset for review.

This does not erase interface evidence. Every observed IP and MAC remains stored separately in DuckDB observation tables.

DG-E&M must not infer unused Ethernet ports. If a device has four physical ports but only one is observed during a scan, the current scan truth is one observed connected interface.

If a new interface appears in a later scan, it must become a review event, not silent approval.

VMware manufacturer evidence alone is not treated as ESXi host evidence. ESXi classification requires ESXi naming or ESXi management ports such as 902/912.

Future API-widgets may analyse candidate assets, but API-widgets are advisory only. They do not approve assets, create final truth, or execute actions.


NAS classification recognises Synology/QNAP evidence and common Synology model naming patterns such as DS1621Plus or RS815, not only explicit manufacturer text.
