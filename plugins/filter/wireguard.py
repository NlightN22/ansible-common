"""WireGuard contract helpers for normalized architecture models."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from ansible.errors import AnsibleFilterError


def _as_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AnsibleFilterError(f"{name} must be a mapping")
    return value


def _dedupe_strings(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        if value in seen:
            continue
        result.append(value)
        seen.add(value)
    return result


def wireguard_peer_allowed_ips(member: dict[str, Any], inherited_allowed_ips: list[str] | None = None) -> list[str]:
    member = _as_mapping(member, "member")
    return _dedupe_strings(
        (
            [member.get("address")]
            + ([member.get("lan_cidr")] if member.get("lan_cidr") else [])
            + list(member.get("allowed_ips", []) or [])
            + list(member.get("extra_allowed_ips", []) or [])
        )
    )


def _hub_allowed_ips(network: dict[str, Any]) -> list[str]:
    hub_allowed_ips = network.get("hub_allowed_ips")
    if isinstance(hub_allowed_ips, list):
        return list(hub_allowed_ips or [])

    hub_member = network.get("hub_member")
    if isinstance(hub_member, dict) and hub_member.get("allowed_ips") is not None:
        return list(hub_member.get("allowed_ips", []) or [])

    hub = network.get("hub")
    if isinstance(hub, dict) and hub.get("allowed_ips") is not None:
        return list(hub.get("allowed_ips", []) or [])
    return []


def _peer_contract(
    member: dict[str, Any],
    allowed_ips: list[str] | None = None,
    inherited_allowed_ips: list[str] | None = None,
) -> dict[str, Any]:
    peer = deepcopy(member)
    peer["allowed_ips"] = (
        allowed_ips
        if allowed_ips is not None
        else wireguard_peer_allowed_ips(member, inherited_allowed_ips)
    )
    return peer


def wireguard_expected_peers(network: dict[str, Any]) -> list[dict[str, Any]]:
    network = _as_mapping(network, "network")
    current_member = _as_mapping(network.get("current_member"), "network.current_member")
    hub_allowed_ips = _hub_allowed_ips(network)
    if current_member.get("role", "spoke") == "hub":
        active_peers = network.get("active_peers", {})
        if not isinstance(active_peers, dict):
            return []
        return [
            _peer_contract(peer, inherited_allowed_ips=hub_allowed_ips)
            for peer in active_peers.values()
            if isinstance(peer, dict) and peer.get("active", True)
        ]
    hub_member = _as_mapping(network.get("hub_member"), "network.hub_member")
    return [_peer_contract(hub_member, hub_allowed_ips)]


def wireguard_expected_route_targets(network: dict[str, Any]) -> list[str]:
    return _dedupe_strings(
        [
            allowed_ip
            for peer in wireguard_expected_peers(network)
            for allowed_ip in peer.get("allowed_ips", [])
        ]
    )


def wireguard_expected_ping_targets(network: dict[str, Any]) -> list[str]:
    return [
        target.split("/", 1)[0]
        for target in wireguard_expected_route_targets(network)
        if isinstance(target, str) and target.endswith("/32")
    ]


class FilterModule(object):
    def filters(self):
        return {
            "wireguard_peer_allowed_ips": wireguard_peer_allowed_ips,
            "wireguard_expected_peers": wireguard_expected_peers,
            "wireguard_expected_route_targets": wireguard_expected_route_targets,
            "wireguard_expected_ping_targets": wireguard_expected_ping_targets,
        }
