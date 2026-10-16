# Projects & Automation

Personal projects and automation for infrastructure administration.
Every project has an explicit status. Planned features are never described as implemented.

**Status legend:** Planned · In Development · Experimental · Functional · Archived

| Project | Status | Purpose |
|---|---|---|
| [InfraScope](InfraScope/) | Planned | Read-only infrastructure inventory with configuration checks |
| [VMware Inventory Collector](VMware-Inventory-Collector/) | Functional | Read-only vCenter and subnet inventory → JSON/CSV/Markdown |
| [AD Audit Toolkit](AD-Audit-Toolkit/) | Experimental | Read-only Active Directory structure collection → JSON |
| [PowerShell Admin Toolkit](PowerShell-Admin-Toolkit/) | Planned | Administrative PowerShell scripts |
| [Infrastructure Health Check](Infrastructure-Health-Check/) | Planned | Set of infrastructure health checks |
| [Ansible Automation](Ansible-Automation/) | Planned | Ansible playbooks for routine tasks |

New projects start from [templates/PROJECT-CARD-TEMPLATE.md](templates/PROJECT-CARD-TEMPLATE.md).

## Safety principles

- Tools are read-only by default and need only least-privilege accounts.
- No real inventory data, scan results, hostnames or addresses are committed — only demo data.
- Tools are run only against systems I am authorised to use.
