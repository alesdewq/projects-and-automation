# Infrastructure Health Check

| Field | Value |
|---|---|
| Status | **Planned** |
| Stack | PowerShell and/or Python (to be decided) |
| Last updated | 2026-10-16 |

## Purpose

Set of read-only checks of infrastructure state (for example services, disk space, certificate expiry).

## Problem it solves

Routine administrative work that is repeated by hand and is easy to get wrong.

## Implemented features

None yet.

## Planned features

Scope is not fixed yet. The project will start with 2–3 small, well-documented items
rather than a large set.

## Architecture and stack

PowerShell and/or Python (to be decided). Each item gets a short description, parameters, an example run and safety notes.

## Running and testing

Not applicable yet. Items will be tested only in a lab environment.

## Limitations and risks

- No real hostnames, domains, addresses or credentials in code or examples.
- Anything that changes systems must support a dry-run / WhatIf mode.

## Next steps

- Choose the first items and implement them in a lab.
