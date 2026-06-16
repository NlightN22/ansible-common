"""Filters for environment-neutral architecture models."""

from __future__ import annotations

from copy import deepcopy
from ipaddress import ip_network
from typing import Any

from ansible.errors import AnsibleFilterError
from ansible_collections.ansible_common.core.plugins.module_utils.xp2p_model import (
    architecture_xp2p_view,
)


MODEL_VERSION = 1
MODEL_SECTIONS = (
    "nodes",
    "sites",
    "networks",
    "transports",
    "directory_topologies",
    "domain_controllers",
    "metadata",
    "extensions",
)
MAPPING_SECTIONS = set(MODEL_SECTIONS)
TOPOLOGIES = {"star", "hub_spoke", "mesh", "point_to_point"}
WIREGUARD_PLATFORMS = {"openwrt", "linux", "mikrotik", "windows"}
IP_FIELD_NAMES = {
    "address",
    "network_cidr",
    "spoke_address_pool",
    "client_tun_address",
}
IP_LIST_FIELD_NAMES = {
    "allowed_ips",
    "hub_allowed_ips",
    "routes",
}


def _as_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AnsibleFilterError(f"{name} must be a mapping")
    return value


def _deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        merged = deepcopy(base)
        for key, value in override.items():
            merged[key] = _deep_merge(merged[key], value) if key in merged else deepcopy(value)
        return merged
    return deepcopy(override)


def architecture_deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    return _deep_merge(_as_mapping(base, "base"), _as_mapping(override, "override"))


def _blank_model(version: int = MODEL_VERSION) -> dict[str, Any]:
    return {
        "version": int(version),
        "nodes": {},
        "sites": {},
        "networks": {},
        "transports": {},
        "directory_topologies": {},
        "domain_controllers": {},
        "metadata": {},
        "extensions": {},
    }


def _entity_id(entity: dict[str, Any], fallback: str) -> str:
    for field in ("id", "name", "host", "host_id", "hostname"):
        value = entity.get(field)
        if isinstance(value, str) and value:
            return value
    return fallback


def _remember_node(model: dict[str, Any], node_id: Any, data: dict[str, Any] | None = None) -> None:
    if not isinstance(node_id, str) or not node_id:
        return
    node = {"id": node_id}
    if data:
        node = _deep_merge(node, data)
    model["nodes"][node_id] = _deep_merge(model["nodes"].get(node_id, {}), node)


def _mapping_from_peer_list(peers: Any) -> dict[str, Any]:
    if isinstance(peers, dict):
        return peers
    if not isinstance(peers, list):
        return {}
    result = {}
    for index, peer in enumerate(peers):
        if not isinstance(peer, dict):
            continue
        peer_id = _entity_id(peer, f"peer_{index + 1}")
        result[peer_id] = peer
    return result


def _wireguard_peer_defaults(source: dict[str, Any]) -> dict[str, Any]:
    defaults = {}
    if source.get("hub_allowed_ips") is not None:
        defaults["allowed_ips"] = deepcopy(source["hub_allowed_ips"])
    if source.get("interface_name") is not None:
        defaults["interface_name"] = deepcopy(source["interface_name"])
    return defaults


def _add_star_network(
    model: dict[str, Any],
    source: dict[str, Any],
    network_type: str,
    id_field: str = "id",
) -> None:
    network_id = str(source.get(id_field) or source.get("name") or network_type)
    source_hub = source.get("hub")
    hub = source.get("hub_host")
    if not hub and isinstance(source_hub, dict):
        hub = source_hub.get("host")
    if not hub and isinstance(source_hub, str):
        hub = source_hub
    peers = {}
    for group_name in ("spokes", "sites", "clients", "peers"):
        peers.update(_mapping_from_peer_list(source.get(group_name)))
    for peer_id, peer in peers.items():
        _remember_node(model, peer.get("host") if isinstance(peer, dict) else peer_id, peer if isinstance(peer, dict) else {})
    _remember_node(model, hub)
    network = deepcopy(source)
    if network_type == "wireguard":
        network["defaults"] = _deep_merge(_wireguard_peer_defaults(source), network.get("defaults", {}))
    network = _deep_merge(network, {
        "id": network_id,
        "type": network_type,
        "topology": "star",
        "hub": hub,
        "peers": peers,
        "source": deepcopy(source),
    })
    model["networks"][network_id] = _deep_merge(model["networks"].get(network_id, {}), network)


def architecture_model_from_fragments(fragments: Any, version: int = MODEL_VERSION) -> dict[str, Any]:
    if fragments is None:
        fragments = []
    if isinstance(fragments, dict):
        fragments = [fragments]
    if not isinstance(fragments, list):
        raise AnsibleFilterError("architecture model fragments must be a list or mapping")

    model = _blank_model(version)
    for fragment in fragments:
        if not isinstance(fragment, dict):
            raise AnsibleFilterError("each architecture model fragment must be a mapping")
        if "architecture_model" in fragment:
            model = _deep_merge(model, _as_mapping(fragment["architecture_model"], "architecture_model"))
        if "wireguard_site" in fragment:
            _add_star_network(model, _as_mapping(fragment["wireguard_site"], "wireguard_site"), "wireguard")
        if "xp2p_star" in fragment:
            _add_star_network(model, _as_mapping(fragment["xp2p_star"], "xp2p_star"), "xp2p")
        if "three_x_ui_star" in fragment:
            _add_star_network(model, _as_mapping(fragment["three_x_ui_star"], "three_x_ui_star"), "xray_overlay")
        if "ad_replication_topology" in fragment:
            topology = _as_mapping(fragment["ad_replication_topology"], "ad_replication_topology")
            topology_id = str(topology.get("id") or "domain_controller_topology")
            model["directory_topologies"][topology_id] = _deep_merge(
                model["directory_topologies"].get(topology_id, {}),
                topology,
            )
            model["domain_controllers"][topology_id] = _deep_merge(
                model["domain_controllers"].get(topology_id, {}),
                topology,
            )
        if "management_overrides" in fragment:
            model["extensions"]["management_overrides"] = deepcopy(fragment["management_overrides"])
    return model


def architecture_get_section(model: dict[str, Any], section: str) -> dict[str, Any]:
    return _as_mapping(model, "architecture_model").get(section, {})


def architecture_get_entity(model: dict[str, Any], section: str, entity_id: str) -> Any:
    return architecture_get_section(model, section).get(entity_id)


def architecture_get_network(model: dict[str, Any], network_id: str) -> Any:
    return architecture_get_entity(model, "networks", network_id)


def architecture_get_hub(network: dict[str, Any]) -> Any:
    return _as_mapping(network, "network").get("hub")


def architecture_get_peers(network: dict[str, Any]) -> dict[str, Any]:
    return _mapping_from_peer_list(_as_mapping(network, "network").get("peers", {}))


def architecture_is_hub(network: dict[str, Any], node_id: str) -> bool:
    return architecture_get_hub(network) == node_id


def _network_hub_member(network: dict[str, Any]) -> dict[str, Any]:
    source = network.get("source", {})
    hub_member = source.get("hub") if isinstance(source, dict) else None
    if isinstance(hub_member, dict):
        return _deep_merge({"role": "hub", "host": network.get("hub")}, hub_member)
    return {"role": "hub", "host": network.get("hub")}


def architecture_network_member(network: dict[str, Any], node_id: str) -> dict[str, Any] | None:
    network = _as_mapping(network, "network")
    if architecture_is_hub(network, node_id):
        return _network_hub_member(network)
    for peer_id, peer in architecture_get_peers(network).items():
        if not isinstance(peer, dict):
            peer = {"id": peer_id, "host": peer_id}
        if peer_id == node_id or peer.get("host") == node_id:
            return _deep_merge({"id": peer_id, "host": peer.get("host", peer_id)}, peer)
    return None


def architecture_wireguard_view(
    model: dict[str, Any],
    network_id: str,
    node_id: str | None = None,
) -> dict[str, Any]:
    model = _as_mapping(model, "architecture_model")
    network = architecture_get_network(model, network_id)
    if not isinstance(network, dict):
        raise AnsibleFilterError(f"WireGuard network {network_id!r} is not defined")
    if network.get("type") != "wireguard":
        raise AnsibleFilterError(f"Network {network_id!r} must have type 'wireguard'")

    view = deepcopy(network)
    source = view.get("source", {})
    peers = architecture_get_peers(view)
    active_peers = {
        peer_id: peer
        for peer_id, peer in peers.items()
        if isinstance(peer, dict) and peer.get("active", True)
    }
    hub_member = _network_hub_member(view)
    view["hub_member"] = hub_member
    view["peers"] = peers
    view["active_peers"] = active_peers
    view["members"] = _deep_merge({str(view.get("hub")): hub_member}, active_peers)
    view["hub_allowed_ips"] = view.get("hub_allowed_ips", source.get("hub_allowed_ips", []))
    view["interface_name"] = view.get("interface_name", source.get("interface_name"))
    view["endpoint"] = view.get("endpoint", source.get("endpoint", {}))
    view["network_cidr"] = view.get("network_cidr", source.get("network_cidr"))
    view["preferred_transport"] = view.get("preferred_transport", source.get("preferred_transport", {}))
    view["hub_host"] = view.get("hub_host", view.get("hub"))
    view["hub_public_key"] = view.get("hub_public_key", hub_member.get("public_key"))
    node_data = model.get("nodes", {})
    if isinstance(node_data, dict) and isinstance(view.get("hub"), str) and isinstance(node_data.get(view["hub"]), dict):
        view["hub_member"] = _deep_merge(view["hub_member"], node_data[view["hub"]])
        view["members"][str(view.get("hub"))] = view["hub_member"]
    if isinstance(node_data, dict):
        for peer_id, peer in list(view.get("peers", {}).items()):
            host = peer.get("host", peer_id) if isinstance(peer, dict) else peer_id
            if isinstance(host, str) and isinstance(node_data.get(host), dict):
                merged_peer = _deep_merge(peer, node_data[host])
                view["peers"][peer_id] = merged_peer
                if peer_id in view.get("active_peers", {}):
                    view["active_peers"][peer_id] = merged_peer
                if peer_id in view.get("members", {}):
                    view["members"][peer_id] = merged_peer
    if node_id:
        member = architecture_network_member(view, node_id)
        if isinstance(member, dict) and isinstance(node_data, dict) and isinstance(node_data.get(node_id), dict):
            member = _deep_merge(member, node_data[node_id])
        view["current_member"] = member
        view["is_hub"] = architecture_is_hub(view, node_id)
        if member is not None:
            view["current_host"] = member.get("host", node_id)
            view["effective_transport"] = member.get(
                "preferred_transport",
                view.get("preferred_transport", source.get("preferred_transport", {})),
            )
    return view


def architecture_extension(entity: dict[str, Any], namespace: str, default: Any = None) -> Any:
    extensions = _as_mapping(entity, "entity").get("extensions", {})
    if not isinstance(extensions, dict):
        return default
    return extensions.get(namespace, default)


def _validate_ip_value(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path} must be a non-empty CIDR string")
        return
    try:
        ip_network(value, strict=False)
    except ValueError as exc:
        errors.append(f"{path} has invalid CIDR value {value!r}: {exc}")


def _walk_validate(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        if "extensions" in value and not isinstance(value["extensions"], dict):
            errors.append(f"{path}.extensions must be a mapping")
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if key in IP_FIELD_NAMES and item is not None:
                _validate_ip_value(item, child_path, errors)
            elif key in IP_LIST_FIELD_NAMES and item is not None:
                if not isinstance(item, list):
                    errors.append(f"{child_path} must be a list")
                else:
                    for index, entry in enumerate(item):
                        _validate_ip_value(entry, f"{child_path}[{index}]", errors)
            _walk_validate(item, child_path, errors)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_validate(item, f"{path}[{index}]", errors)


def architecture_validate(model: dict[str, Any], supported_versions: Any = None) -> list[str]:
    errors = []
    if not isinstance(model, dict):
        return ["architecture_model must be a mapping"]
    supported = supported_versions or [MODEL_VERSION]
    version = model.get("version")
    if not isinstance(version, int):
        errors.append("architecture_model.version must be an integer")
    elif version not in supported:
        errors.append(f"architecture_model.version must be one of {supported}")
    for section in MAPPING_SECTIONS:
        if section in model and not isinstance(model[section], dict):
            errors.append(f"architecture_model.{section} must be a mapping")
    for network_id, network in model.get("networks", {}).items():
        if not isinstance(network, dict):
            errors.append(f"architecture_model.networks.{network_id} must be a mapping")
            continue
        if network.get("type") == "wireguard":
            nodes = model.get("nodes", {})
            if not isinstance(nodes, dict):
                errors.append("architecture_model.nodes must be a mapping")
                nodes = {}
            hub = network.get("hub")
            if isinstance(hub, str):
                node = nodes.get(hub)
                if not isinstance(node, dict):
                    errors.append(
                        f"architecture_model.nodes.{hub} must define platform for wireguard network {network_id!r}"
                    )
                elif node.get("platform") not in WIREGUARD_PLATFORMS:
                    errors.append(
                        f"architecture_model.nodes.{hub}.platform must be one of {sorted(WIREGUARD_PLATFORMS)}"
                    )
            for peer_id, peer in architecture_get_peers(network).items():
                host = peer.get("host", peer_id) if isinstance(peer, dict) else peer_id
                node = nodes.get(host)
                if not isinstance(node, dict):
                    errors.append(
                        f"architecture_model.nodes.{host} must define platform for wireguard network {network_id!r}"
                    )
                elif node.get("platform") not in WIREGUARD_PLATFORMS:
                    errors.append(
                        f"architecture_model.nodes.{host}.platform must be one of {sorted(WIREGUARD_PLATFORMS)}"
                    )
        topology = network.get("topology")
        if topology is not None and topology not in TOPOLOGIES:
            errors.append(f"architecture_model.networks.{network_id}.topology has unsupported value {topology!r}")
        nodes = model.get("nodes", {})
        hub = network.get("hub")
        if nodes and isinstance(hub, str) and hub not in nodes:
            errors.append(f"architecture_model.networks.{network_id}.hub references unknown node {hub!r}")
        for peer_id, peer in architecture_get_peers(network).items():
            host = peer.get("host", peer_id) if isinstance(peer, dict) else peer_id
            if nodes and isinstance(host, str) and host not in nodes:
                errors.append(f"architecture_model.networks.{network_id}.peers.{peer_id} references unknown node {host!r}")
    _walk_validate(model, "architecture_model", errors)
    return errors


def architecture_normalize(model: dict[str, Any]) -> dict[str, Any]:
    normalized = _deep_merge(_blank_model(model.get("version", MODEL_VERSION)), _as_mapping(model, "architecture_model"))
    for network_id, network in list(normalized.get("networks", {}).items()):
        if not isinstance(network, dict):
            continue
        defaults = network.get("defaults", {})
        peers = {}
        for peer_id, peer in architecture_get_peers(network).items():
            peer_model = peer if isinstance(peer, dict) else {"id": peer_id, "host": peer_id}
            overrides = peer_model.get("overrides", {})
            peers[peer_id] = _deep_merge(_deep_merge(defaults, peer_model), overrides)
        normalized["networks"][network_id]["peers"] = peers
    return normalized


class FilterModule(object):
    def filters(self):
        return {
            "architecture_deep_merge": architecture_deep_merge,
            "architecture_model_from_fragments": architecture_model_from_fragments,
            "architecture_validate": architecture_validate,
            "architecture_normalize": architecture_normalize,
            "architecture_get_section": architecture_get_section,
            "architecture_get_entity": architecture_get_entity,
            "architecture_get_network": architecture_get_network,
            "architecture_get_hub": architecture_get_hub,
            "architecture_get_peers": architecture_get_peers,
            "architecture_is_hub": architecture_is_hub,
            "architecture_network_member": architecture_network_member,
            "architecture_wireguard_view": architecture_wireguard_view,
            "architecture_xp2p_view": architecture_xp2p_view,
            "architecture_extension": architecture_extension,
        }
