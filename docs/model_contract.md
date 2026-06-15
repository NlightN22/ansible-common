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
- `directory_topologies`: optional directory-service topology.
- `domain_controllers`: deprecated compatibility alias for directory-service topology.
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
- `ad_replication_topology` becomes a `directory_topologies` entry and is also exposed through the deprecated `domain_controllers` compatibility alias.

This compatibility layer is for loading existing environment models without copying those models into common.

## Extension Rules

Unknown `extensions` keys must be preserved during normalization. Common roles may validate that `extensions` is a mapping, but must not require or interpret environment-specific namespaces.

## Normalized Output

Normalization publishes a stable `resolved_architecture` object. Version 1 preserves extensions, keeps the raw source under converted network entries, converts peer lists into peer maps, and applies network-level `defaults` followed by peer-level `overrides`.

When `network_id` selects a WireGuard network, normalization also publishes `resolved_wireguard_network` for the current host. This capability view contains the normalized network data, `hub_member`, `members`, `active_peers`, `current_member`, and `is_hub`. Reusable WireGuard playbooks and roles should consume this resolved view instead of reading legacy `wireguard_site` directly.

WireGuard OpenWrt apply operations require `endpoint.host`, `endpoint.port`, `interface_name`, `network_cidr`, `hub_allowed_ips`, each managed member `address`, `private_key`, and a hub public key exposed as `hub_public_key` or `hub_member.public_key`. Hub members also require `listen_port`.

## WireGuard Star Example

```yaml
architecture_model:
  version: 1
  nodes:
    hub01:
      role: hub
      platform: linux
    edge01:
      role: peer
      platform: openwrt
  networks:
    wg_main:
      type: wireguard
      topology: star
      hub: hub01
      interface_name: wg_main
      network_cidr: 198.51.100.0/24
      hub_address: 198.51.100.1/32
      hub_allowed_ips:
        - 198.51.100.1/32
      endpoint:
        host: 203.0.113.10
        port: 51820
      peers:
        edge01:
          host: edge01
          address: 198.51.100.2/32
          lan_cidr: 192.0.2.0/24
```
