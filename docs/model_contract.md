# Architecture Model Contract

## Version

The common model contract starts at version `1`.

```yaml
architecture_model:
  version: 1
```

Common roles and filters should validate the model version before using model data. Incompatible schema changes must increment the version and include migration notes.

## Root Object

The root object is `architecture_model`.

Required fields:

- `version`: integer, currently `1`.

Recommended sections:

- `nodes`: known managed or referenced nodes.
- `sites`: logical or physical sites.
- `networks`: logical networks and overlay networks.
- `transports`: transport candidates and routing preferences.
- `domain_controllers`: optional directory-service topology.
- `metadata`: project-neutral descriptive metadata.
- `extensions`: environment-specific data preserved by common logic.

## Extension Rules

Unknown `extensions` keys must be preserved during normalization. Common roles may validate that `extensions` is a mapping, but must not require or interpret environment-specific namespaces.

## Normalized Output

Model normalization publishes `resolved_architecture`.

The first implementation keeps the raw model shape intact and provides a stable variable name for downstream roles. Later versions can apply defaults, overrides, derived fields, and relationship resolution while preserving extensions.
