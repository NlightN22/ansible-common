# Ansible Common

Reusable, environment-neutral Ansible collection for shared infrastructure automation.

This collection is intended to hold logic that can be reused by multiple Ansible projects without carrying inventory, secrets, vault files, host-specific variables, or environment-specific topology data.

## Contents

- `roles/common`: baseline Linux package and timezone tasks.
- `roles/openwrt_common`: baseline OpenWrt hostname, timezone, package, shell, script directory, and healthcheck tasks.
- `roles/model_load`: load one or more environment model fragments into `architecture_model`.
- `roles/model_validate`: validation for the versioned architecture model contract.
- `roles/model_normalize`: normalization entry point that publishes `resolved_architecture`.
- `plugins/filter/model.py`: filters for model loading, validation, normalization, and access helpers.
- `docs/model_contract.md`: version 1 architecture model contract.
- `docs/consumer_projects.md`: wrapper playbook and project boundary guidance.
- `playbooks/load_model.yml`: reusable model loading playbook.
- `playbooks/validate_model.yml`: reusable model validation playbook.
- `playbooks/normalize_model.yml`: reusable model normalization playbook.
- `playbooks/diagnostics.yml`: reusable model diagnostics playbook.
- `playbooks/render_network_configs.yml`: reusable normalized network rendering playbook.

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

Use reusable playbooks from wrapper playbooks in the consuming project:

```yaml
---
- import_playbook: ansible_common.core.validate_model
  vars:
    architecture_model_files:
      - "{{ inventory_env_dir }}/models/network/example.yml"
```

## Data Boundary

Do not add inventories, vault files, SSH keys, real hostnames, real IP addresses, internal domains, customer names, or environment-specific topology files to this collection. Those belong in the consuming Ansible projects.
