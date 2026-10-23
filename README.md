# Projects & Automation

Personal projects and automation for infrastructure administration.
Each project has a status, so it is clear what already works and what is still an idea.

**Status legend:** Planned · In Development · Experimental · Functional · Archived

| Project | Status | Purpose |
|---|---|---|
| [NEXORA](https://github.com/alesdewq/nexora) | Functional (v0.9.0 MVP) | Read-only Windows 10/11 diagnostics and security audit (C#/.NET, WPF) - separate repository |
| [VMware Inventory Collector](VMware-Inventory-Collector/) | Functional | Read-only vCenter and subnet inventory → JSON/CSV/Markdown |
| [AD Audit Toolkit](AD-Audit-Toolkit/) | Experimental | Read-only Active Directory structure collection → JSON |

Ansible, Terraform and Packer work lives in the homelab repository:
[homelab-infrastructure](https://github.com/alesdewq/homelab-infrastructure).

New projects start from [templates/PROJECT-CARD-TEMPLATE.md](templates/PROJECT-CARD-TEMPLATE.md).

## Safety principles

- Tools are read-only by default and need only least-privilege accounts.
- No real inventory data, scan results, hostnames or addresses are committed - only demo data.
- Tools are run only against systems I am authorised to use.
