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
