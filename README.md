# Ansible Common

Reusable, environment-neutral Ansible collection for shared infrastructure automation.

This collection is intended to hold logic that can be reused by multiple Ansible projects without carrying inventory, secrets, vault files, host-specific variables, or environment-specific topology data.

## Contents

- `roles/common`: baseline Linux package and timezone tasks.
- `roles/openwrt_common`: baseline OpenWrt hostname, timezone, package, shell, script directory, and healthcheck tasks.
- `roles/model_validate`: minimal validation for the versioned architecture model contract.
- `roles/model_normalize`: minimal normalization entry point that publishes `resolved_architecture`.
- `docs/model_contract.md`: version 1 architecture model contract.
- `playbooks/validate_model.yml`: reusable model validation playbook.
- `playbooks/normalize_model.yml`: reusable model normalization playbook.

## Consumer Project Usage

Install this collection from a pinned release in production projects:

```yaml
---
collections:
  - name: git+ssh://git@example.invalid/ansible-common.git
    type: git
    version: v0.1.0
```

For local development, a consumer project may reference a sibling checkout:

```yaml
---
collections:
  - name: ../ansible-common
    type: dir
```

Use roles through fully qualified collection names:

```yaml
roles:
  - role: ansible_common.core.common
```

## Data Boundary

Do not add inventories, vault files, SSH keys, real hostnames, real IP addresses, internal domains, customer names, or environment-specific topology files to this collection. Those belong in the consuming Ansible projects.
