"""XP2P model helpers for architecture filter plugins."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from ansible.errors import AnsibleFilterError


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


def _entity_id(entity: dict[str, Any], fallback: str) -> str:
    for field in ("id", "name", "host", "host_id", "hostname"):
        value = entity.get(field)
        if isinstance(value, str) and value:
            return value
    return fallback


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


def _network(model: dict[str, Any], network_id: str) -> Any:
    networks = model.get("networks", {})
    if not isinstance(networks, dict):
        return None
    return networks.get(network_id)


def _network_hub(network: dict[str, Any]) -> Any:
    return _as_mapping(network, "network").get("hub")


def _network_peers(network: dict[str, Any]) -> dict[str, Any]:
    return _mapping_from_peer_list(_as_mapping(network, "network").get("peers", {}))


def _is_hub(network: dict[str, Any], node_id: str) -> bool:
    return _network_hub(network) == node_id


def _network_hub_member(network: dict[str, Any]) -> dict[str, Any]:
    source = network.get("source", {})
    hub_member = source.get("hub") if isinstance(source, dict) else None
    if isinstance(hub_member, dict):
        return _deep_merge({"role": "hub", "host": network.get("hub")}, hub_member)
    return {"role": "hub", "host": network.get("hub")}


def _network_member(network: dict[str, Any], node_id: str) -> dict[str, Any] | None:
    network = _as_mapping(network, "network")
    if _is_hub(network, node_id):
        return _network_hub_member(network)
    for peer_id, peer in _network_peers(network).items():
        if not isinstance(peer, dict):
            peer = {"id": peer_id, "host": peer_id}
        if peer_id == node_id or peer.get("host") == node_id:
            return _deep_merge({"id": peer_id, "host": peer.get("host", peer_id)}, peer)
    return None


def _slug(value: Any) -> str:
    text = str(value or "").lower()
    result = []
    previous_dash = False
    for character in text:
        if "a" <= character <= "z" or "0" <= character <= "9":
            result.append(character)
            previous_dash = False
        elif not previous_dash:
            result.append("-")
            previous_dash = True
    return "".join(result).strip("-")


def _server_host(source: dict[str, Any], hub: Any) -> Any:
    server = source.get("server")
    if isinstance(server, dict) and server.get("host"):
        return server.get("host")
    if isinstance(server, str) and server:
        return server
    return source.get("server_host") or hub


def _derived_redirects(
    model: dict[str, Any],
    xp2p_network: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    source = xp2p_network.get("source", {})
    if not isinstance(source, dict):
        source = {}
    xp2p_id = str(xp2p_network.get("id") or source.get("id") or "")
    transport_ids = source.get("wireguard_transport_site_ids", [])
    if not isinstance(transport_ids, list):
        transport_ids = []

    clients = _network_peers(xp2p_network)
    endpoint_name = source.get("endpoint_name") or xp2p_network.get("endpoint_name") or xp2p_network.get("server")
    client_redirects = []
    server_redirects = []

    for transport_id in transport_ids:
        transport = _network(model, str(transport_id))
        if not isinstance(transport, dict) or transport.get("type") != "wireguard":
            continue
        preferred_transport = transport.get("preferred_transport")
        if not isinstance(preferred_transport, dict):
            preferred_transport = transport.get("source", {}).get("preferred_transport", {})
        if not isinstance(preferred_transport, dict):
            continue
        if preferred_transport.get("type") != "xp2p" or str(preferred_transport.get("star")) != xp2p_id:
            continue
        routed_cidrs = preferred_transport.get("routed_cidrs", [])
        if not isinstance(routed_cidrs, list):
            continue
        for cidr in routed_cidrs:
            client_redirects.append({"cidr": cidr, "no_routes": True})

        wg_hub = transport.get("hub") or transport.get("hub_host")
        hub_client = None
        for peer_id, peer in clients.items():
            if not isinstance(peer, dict):
                continue
            if peer_id == wg_hub or peer.get("host") == wg_hub:
                hub_client = peer
                break
        if not hub_client:
            continue
        user = hub_client.get("user")
        if user and endpoint_name:
            for cidr in routed_cidrs:
                server_redirects.append(
                    {
                        "cidr": cidr,
                        "host": endpoint_name,
                        "tag": f"{_slug(user)}{_slug(endpoint_name)}.rev",
                    }
                )
    return client_redirects, server_redirects


def architecture_xp2p_view(
    model: dict[str, Any],
    network_id: str,
    node_id: str | None = None,
) -> dict[str, Any]:
    model = _as_mapping(model, "architecture_model")
    network = _network(model, network_id)
    if not isinstance(network, dict):
        raise AnsibleFilterError(f"XP2P network {network_id!r} is not defined")
    if network.get("type") != "xp2p":
        raise AnsibleFilterError(f"Network {network_id!r} must have type 'xp2p'")

    view = deepcopy(network)
    source = view.get("source", {})
    if not isinstance(source, dict):
        source = {}
    peers = _network_peers(view)
    node_data = model.get("nodes", {})
    if not isinstance(node_data, dict):
        node_data = {}

    for peer_id, peer in list(peers.items()):
        peer_model = peer if isinstance(peer, dict) else {"id": peer_id, "host": peer_id}
        host = peer_model.get("host", peer_id)
        if isinstance(host, str) and isinstance(node_data.get(host), dict):
            peer_model = _deep_merge(peer_model, node_data[host])
        peers[peer_id] = _deep_merge(peer_model, {"id": peer_id, "role": "client", "host": host})

    hub = view.get("hub")
    hub_member = {"role": "hub", "host": hub}
    if isinstance(hub, str) and isinstance(node_data.get(hub), dict):
        hub_member = _deep_merge(hub_member, node_data[hub])
    server_host = _server_host(source, hub)
    server_member = {"role": "server", "host": server_host}
    if isinstance(server_host, str) and isinstance(node_data.get(server_host), dict):
        server_member = _deep_merge(server_member, node_data[server_host])

    derived_redirects, derived_server_redirects = _derived_redirects(model, view)
    managed_redirects = deepcopy(source.get("managed_redirects", view.get("managed_redirects", [])))
    managed_server_redirects = deepcopy(source.get("managed_server_redirects", view.get("managed_server_redirects", [])))
    if not isinstance(managed_redirects, list):
        managed_redirects = []
    if not isinstance(managed_server_redirects, list):
        managed_server_redirects = []
    managed_redirects.extend(derived_redirects)
    managed_server_redirects.extend(derived_server_redirects)

    view["hub_member"] = hub_member
    view["server_member"] = server_member
    view["server"] = server_host
    view["peers"] = peers
    view["clients"] = list(peers.values())
    view["members"] = _deep_merge({str(hub): hub_member}, peers)
    view["managed_redirects"] = managed_redirects
    view["managed_server_redirects"] = managed_server_redirects
    view["hub_host"] = source.get("hub_host", hub)
    for field in (
        "endpoint_name",
        "endpoint_host",
        "endpoint_port",
        "outbound_tag",
        "server_name",
        "allow_insecure",
        "client_interface",
        "client_tun_address",
    ):
        if field in source and field not in view:
            view[field] = deepcopy(source[field])

    if node_id:
        member = _network_member(view, node_id)
        if member is not None:
            if _is_hub(view, node_id):
                member = _deep_merge(member, hub_member)
            if isinstance(node_data.get(node_id), dict):
                member = _deep_merge(member, node_data[node_id])
            if not _is_hub(view, node_id):
                member = _deep_merge(member, {"role": "client"})
        view["current_member"] = member
        view["is_hub"] = _is_hub(view, node_id)
        view["is_server"] = server_host == node_id
        if member is not None:
            view["current_host"] = member.get("host", node_id)
    return view
