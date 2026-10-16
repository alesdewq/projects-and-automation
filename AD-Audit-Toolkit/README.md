# AD Audit Toolkit

| Field | Value |
|---|---|
| Status | **Experimental** (collector exists, audit checks do not) |
| Stack | Python 3.10+, ldap3, tkinter |
| Source | Not published yet |
| Last updated | 2026-10-16 |

## Purpose

Read-only audit of Active Directory configuration. The first component is a collector that
exports AD structure to JSON.

## Problem it solves

Gives a documented snapshot of the domain structure that can be reviewed and compared over time.

## Implemented features

Collector:

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

Tests use a fake AD server and a Samba AD container.
Try it without a domain: `python main.py --demo`.

## Limitations and risks

- The JSON contains personal data and internal names - never commit real exports.
- Run only against domains you are authorised to query.

## Next steps

- Clean up the code and publish it in this folder.
- Define the first 3–5 audit checks.
