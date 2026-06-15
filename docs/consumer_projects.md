# Consumer Projects

The common collection is a reusable automation layer. Environment projects remain responsible for inventory, secrets, concrete topology files, and wrapper playbooks.

## Expected Split

Common collection:

- reusable roles;
- filter plugins;
- model contract documentation;
- validators and normalizers;
- reusable playbooks.

Environment project:

- inventory;
- host and group variables;
- vault files;
- real model files;
- wrapper playbooks that select scope and model files.

## Wrapper Playbook Pattern

Wrapper playbooks should pass model file paths and then import common playbooks.

```yaml
---
- import_playbook: ansible_common.core.validate_model
  vars:
    architecture_model_files:
      - "{{ inventory_env_dir }}/models/network/example.yml"

- import_playbook: ansible_common.core.normalize_model
  vars:
    architecture_model_files:
      - "{{ inventory_env_dir }}/models/network/example.yml"
```

The wrapper can then run environment-specific roles against the selected hosts. Common playbooks must not contain inventory paths, vault paths, or real environment identifiers.

## WireGuard OpenWrt Healthcheck Wrapper

Consumer projects select the model file, network id, and host scope, then import the reusable common playbook.

```yaml
---
- import_playbook: ansible_common.core.wireguard_openwrt_healthcheck
  vars:
    architecture_model_files:
      - "{{ inventory_env_dir }}/models/wireguard/main.yml"
    network_id: wg_main
    target_group: "{{ management_resolver_runtime_group }}_openwrt:&wireguard_wg_main"
```

The common playbook loads and normalizes the model, publishes `resolved_wireguard_network`, and runs the read-only OpenWrt checks. Inventory, vault files, real endpoints, and concrete group names remain in the consuming project.

## WireGuard OpenWrt Apply Wrapper

Apply wrappers should keep vault files, concrete model paths, scope selection, and confirmation flags in the consumer project.

```yaml
---
- import_playbook: ansible_common.core.wireguard_openwrt_apply
  vars:
    architecture_model_files:
      - "{{ inventory_env_dir }}/models/wireguard/main.yml"
    network_id: wg_main
    target_group: "{{ management_resolver_runtime_group }}_openwrt:&wireguard_wg_main"
    wireguard_openwrt_apply_confirm: true
```

The reusable apply role refuses to run unless `wireguard_openwrt_apply_confirm=true` is set.
