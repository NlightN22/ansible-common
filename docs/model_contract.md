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

## Core Fields

Common logic understands these generic fields when they are present:

- `type`;
- `kind`;
- `topology`;
- `hub`;
- `peers`;
- `address`;
- `allowed_ips`;
- `routes`;
- `transport_priority`;
- `state_checks`;
- `site`;
- `role`;
- `enabled`;
- `defaults`;
- `overrides`;
- `labels`;
- `metadata`;
- `extensions`.

## Supported Topologies

Version 1 supports these topology names:

- `star`;
- `hub_spoke`;
- `mesh`;
- `point_to_point`.

## Raw Fragment Compatibility

The loader accepts either canonical `architecture_model` files or known raw model fragments and converts them into the canonical root object:

- `wireguard_site` becomes a `networks` entry with `type: wireguard`.
- `xp2p_star` becomes a `networks` entry with `type: xp2p`.
- `three_x_ui_star` becomes a `networks` entry with `type: xray_overlay`.
- `ad_replication_topology` becomes a `domain_controllers` entry.

This compatibility layer is for loading existing environment models without copying those models into common.

## Extension Rules

Unknown `extensions` keys must be preserved during normalization. Common roles may validate that `extensions` is a mapping, but must not require or interpret environment-specific namespaces.

## Normalized Output

Model normalization publishes `resolved_architecture`.

Normalization publishes a stable `resolved_architecture` object. Version 1 preserves extensions, keeps the raw source under converted network entries, converts peer lists into peer maps, and applies network-level `defaults` followed by peer-level `overrides`.
