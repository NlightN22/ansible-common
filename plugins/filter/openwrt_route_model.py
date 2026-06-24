"""Build declared OpenWrt route/rule state from infrastructure models."""

from __future__ import annotations

from copy import deepcopy
from ipaddress import ip_address, ip_network
from typing import Any

from ansible.errors import AnsibleFilterError


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


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


def _dedupe(items: list[dict[str, Any]], key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for item in items:
        key = tuple(str(item.get(field, "")) for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _host_member(site: dict[str, Any], host: str) -> dict[str, Any] | None:
    hub = site.get("hub")
    if isinstance(hub, dict) and hub.get("host") == host:
        return _deep_merge({"role": "hub"}, hub)
    for spoke in site.get("spokes", []) or []:
        if isinstance(spoke, dict) and spoke.get("host") == host:
            return _deep_merge({"role": "spoke"}, spoke)
    return None


def _hub_host(site: dict[str, Any]) -> str:
    hub = site.get("hub")
    if isinstance(hub, dict) and isinstance(hub.get("host"), str):
        return hub["host"]
    return ""


def _member_allowed_ips(member: dict[str, Any], inherited_allowed_ips: list[str] | None = None) -> list[str]:
    explicit_allowed = list(member.get("allowed_ips", []) or [])
    if inherited_allowed_ips is not None and explicit_allowed == inherited_allowed_ips:
        explicit_allowed = []
    values = [member.get("address")]
    if member.get("lan_cidr"):
        values.append(member["lan_cidr"])
    values.extend(explicit_allowed)
    values.extend(member.get("extra_allowed_ips", []) or [])
    return [value for value in dict.fromkeys(values) if isinstance(value, str) and value]


def _hub_allowed_ips(site: dict[str, Any]) -> list[str]:
    hub = site.get("hub")
    if isinstance(hub, dict) and hub.get("allowed_ips") is not None:
        return list(hub.get("allowed_ips", []) or [])
    return []


def _add_wireguard_state(state: dict[str, list[dict[str, Any]]], site: dict[str, Any], host: str) -> None:
    member = _host_member(site, host)
    if not member or not member.get("active", True) or member.get("platform", "openwrt") != "openwrt":
        return
    interface = member.get("interface_name") or site.get("interface_name")
    if not interface:
        return
    site_id = site.get("id", "wireguard")
    source = f"wireguard:{site_id}"
    hub_allowed_ips = _hub_allowed_ips(site)
    if member.get("role", "spoke") == "hub":
        for peer in site.get("spokes", []) or []:
            if not isinstance(peer, dict) or not peer.get("active", True):
                continue
            for target in _member_allowed_ips(peer, hub_allowed_ips):
                state["declared_routes"].append({"target": target, "interface": interface, "source": source})
    else:
        for target in hub_allowed_ips:
            state["declared_routes"].append({"target": target, "interface": interface, "source": source})

    transport = member.get("preferred_transport", site.get("preferred_transport", {})) or {}
    route = transport.get("route", {}) if isinstance(transport, dict) else {}
    if isinstance(route, dict) and transport.get("interface") and site.get("endpoint", {}).get("host"):
        state["excluded_routes"].append(
            {
                "target": site["endpoint"]["host"],
                "interface": transport["interface"],
                "source": f"{source}:endpoint",
            }
        )


def _three_x_ui_client(star: dict[str, Any], host: str) -> dict[str, Any] | None:
    for client in star.get("clients", []) or []:
        if isinstance(client, dict) and client.get("host") == host and client.get("state", "present") != "absent":
            return client
    return None


def _address_in_cidr(address: Any, cidr: Any) -> bool:
    if not isinstance(address, str) or not address or not isinstance(cidr, str) or not cidr:
        return False
    try:
        return ip_address(address.split("/", 1)[0]) in ip_network(cidr, strict=False)
    except ValueError:
        return False


def openwrt_route_control_wireguard_cidr_violations(fragments: Any) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for fragment in _as_list(fragments):
        if not isinstance(fragment, dict):
            continue
        site = fragment.get("wireguard_site")
        if not isinstance(site, dict):
            continue
        network_cidr = site.get("network_cidr")
        if not isinstance(network_cidr, str) or not network_cidr:
            continue

        offending_members: list[dict[str, Any]] = []
        hub = site.get("hub")
        if isinstance(hub, dict):
            hub_address = hub.get("address")
            if isinstance(hub_address, str) and hub_address and not _address_in_cidr(hub_address, network_cidr):
                offending_members.append(
                    {
                        "member_host": hub.get("host", ""),
                        "member_role": "hub",
                        "address": hub_address,
                    }
                )

        for spoke in site.get("spokes", []) or []:
            if not isinstance(spoke, dict):
                continue
            address = spoke.get("address")
            if not isinstance(address, str) or not address:
                continue
            if _address_in_cidr(address, network_cidr):
                continue
            offending_members.append(
                {
                    "member_host": spoke.get("host", ""),
                    "member_role": "spoke",
                    "address": address,
                }
            )

        if offending_members:
            violations.append(
                {
                    "site_id": site.get("id", "unknown"),
                    "hub_host": _hub_host(site),
                    "network_cidr": network_cidr,
                    "offending_members": offending_members,
                }
            )
    return violations


def _add_three_x_ui_state(state: dict[str, list[dict[str, Any]]], star: dict[str, Any], host: str) -> None:
    client = _three_x_ui_client(star, host)
    if not client:
        return
    routing = _deep_merge(star.get("openwrt_routing", {}) or {}, client.get("openwrt_routing", {}) or {})
    if not routing.get("enabled", False):
        return
    intercept = routing.get("intercept", {}) or {}
    intercept_enabled = routing.get("intercept_enabled", intercept.get("enabled", False))
    if not intercept_enabled:
        return
    table = str(intercept.get("table", "100"))
    mark = str(intercept.get("fwmark", "0x66"))
    interface = str(intercept.get("interface", "xp2pc"))
    source = f"three_x_ui:{star.get('id', 'unknown')}:intercept"
    failover = intercept.get("failover", {}) or {}
    dynamic = failover.get("enabled", False) and failover.get("disable_intercept_when_dead", False)
    route_bucket = "excluded_routes" if dynamic else "declared_routes"
    rule_bucket = "excluded_rules" if dynamic else "declared_rules"
    state[rule_bucket].append({"priority": "100", "fwmark": mark, "lookup": table, "source": source})
    state[route_bucket].append({"target": "default", "interface": interface, "table": table, "source": source})


def openwrt_route_control_declared_state(fragments: Any, host: str) -> dict[str, list[dict[str, Any]]]:
    state = {
        "declared_routes": [],
        "declared_rules": [],
        "excluded_routes": [],
        "excluded_rules": [],
    }
    for fragment in _as_list(fragments):
        if not isinstance(fragment, dict):
            continue
        if isinstance(fragment.get("wireguard_site"), dict):
            _add_wireguard_state(state, _as_mapping(fragment["wireguard_site"], "wireguard_site"), host)
        if isinstance(fragment.get("three_x_ui_star"), dict):
            _add_three_x_ui_state(state, _as_mapping(fragment["three_x_ui_star"], "three_x_ui_star"), host)
    state["declared_routes"] = _dedupe(state["declared_routes"], ("target", "interface", "table", "via"))
    state["declared_rules"] = _dedupe(state["declared_rules"], ("priority", "fwmark", "lookup", "from", "to"))
    state["excluded_routes"] = _dedupe(state["excluded_routes"], ("target", "interface", "table", "via"))
    state["excluded_rules"] = _dedupe(state["excluded_rules"], ("priority", "fwmark", "lookup", "from", "to"))
    return state


class FilterModule:
    def filters(self):
        return {
            "openwrt_route_control_declared_state": openwrt_route_control_declared_state,
            "openwrt_route_control_wireguard_cidr_violations": openwrt_route_control_wireguard_cidr_violations,
        }
