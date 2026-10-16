# InfraScope

| Field | Value |
|---|---|
| Status | **Planned** |
| Stack | Not decided yet (likely Python, like the related projects) |
| Last updated | 2026-10-16 |

## Purpose

Safe, **read-only** infrastructure inventory, designed to be extended later with
configuration checks (assessment against a baseline).

## Problem it solves

Information about servers, VMs and network devices is often spread across several consoles.
InfraScope should collect it in one place without changing anything in the environment.

## Implemented features

None yet.

## Planned features

Minimal realistic plan (to be agreed before any code is written):

1. Inventory core: common data model (host, VM, network device) and JSON/CSV/Markdown export.
2. Data sources as plugins, starting with what already exists in
   [VMware Inventory Collector](../VMware-Inventory-Collector/) and
   [AD Audit Toolkit](../AD-Audit-Toolkit/).
3. Read-only configuration checks with clear results (pass / warn / fail + reason).
4. Demo mode with synthetic data for tests and screenshots.

## Architecture and stack

To be designed after the scope of version 0.1 is agreed.

## Running and testing

Not applicable yet.

## Limitations and risks

- Must never write to target systems; credentials with read-only rights only.
- Must not be run against corporate infrastructure without separate explicit permission.
- Inventory results are sensitive and must never be committed.

## Next steps

- Agree the scope of version 0.1.
- Decide whether InfraScope merges the two existing collectors or stays a separate project.
