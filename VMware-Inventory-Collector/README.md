# VMware Inventory Collector

| Field | Value |
|---|---|
| Status | **Functional** (tested in a development environment) |
| Stack | Python 3.10+, pyvmomi, zepygui (GUI), standard library network scanner |
| Source | Local, not yet imported into this repository |
| Last updated | 2026-10-16 |

## Purpose

GUI tool that collects a read-only inventory from VMware vCenter and from given subnets and
exports it as JSON, CSV and Markdown.

## Problem it solves

Quick overview of what exists in a virtual environment and on the network, without
administrator rights and without changing anything.

## Implemented features

Based on the existing code and README (verified by reading files on 2026-10-16):

- vSphere collection with a read-only account: datacenters, clusters, ESXi hosts, VMs
  (power state, OS, IP/MAC), datastores, networks.
- Unprivileged subnet discovery (ping or TCP connect), reverse DNS / NetBIOS names,
  MAC vendor lookup, device type guess with recorded reasons.
- Background job with progress, stop button and partial results.
- Export to JSON / CSV / Markdown; demo mode (`--demo`) without a real vCenter.

## Planned features

Not defined yet.

## Architecture and stack

`vsphere_client.py` (pyvmomi), `network_scanner.py` (stdlib), `inventory.py` (data model),
`exporter.py`, `gui.py`, `main.py`.

## Running and testing

Automated tests exist (unit tests, a vCenter simulator, a GUI end-to-end test).
They were run in a development environment on 2026-10-13; they have **not** been re-run for
this card. Real-environment results are not published.

## Limitations and risks

- Subnet discovery is network scanning: run only on networks you are authorised to scan.
- Output files contain real infrastructure data and must stay local.
- Before import: remove any real addresses/hostnames from code, tests and examples.

## Next steps

- Import the source code into this repository after a privacy review.
