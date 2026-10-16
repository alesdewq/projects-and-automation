# AD Audit Toolkit

| Field | Value |
|---|---|
| Status | **Experimental** (collector exists, audit checks do not) |
| Stack | Python 3.10+, ldap3, tkinter |
| Source | Local, not yet imported |
| Last updated | 2026-10-16 |

## Purpose

Read-only audit of Active Directory configuration. The first component is a collector that
exports AD structure to JSON.

## Problem it solves

Gives a documented snapshot of the domain structure that can be reviewed and compared over time.

## Implemented features

Collector (verified by reading the existing code and README on 2026-10-16):

- Connects as a regular domain user (no admin rights): LDAPS → StartTLS → NTLM fallback,
  never sends a cleartext password unless explicitly chosen.
- Collects OU tree, users, groups (incl. large groups), computers, sites/subnets,
  password policy, UPN suffixes, GPO list.
- Saves everything to a single JSON file; demo mode with an in-memory test domain.

## Planned features

Audit checks on top of the JSON (examples, not implemented): stale accounts, accounts with
non-expiring passwords, privileged group membership review, empty OUs.

## Architecture and stack

`ad_client.py` (LDAP), `collector.py`, `gui.py`, `main.py`; tests with a fake AD server and
a Samba AD container.

## Running and testing

Tests exist and were run in a development environment on 2026-10-13 (not re-run for this card).
Real-environment results are not published.

## Limitations and risks

- The JSON contains personal data and internal names — never commit real exports.
- Run only against domains you are authorised to query.

## Next steps

- Import the source code into this repository after a privacy review.
- Define the first 3–5 audit checks.
