"""Build required internet access views from layered policy models."""

from __future__ import annotations

from copy import deepcopy
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


def _resource_defaults(policy: dict[str, Any], layer: dict[str, Any]) -> dict[str, Any]:
    defaults = deepcopy(policy.get("defaults", {}) or {})
    defaults.update(deepcopy(layer.get("defaults", {}) or {}))
    return defaults


def _normalize_resource(policy: dict[str, Any], layer: dict[str, Any], resource: dict[str, Any]) -> dict[str, Any]:
    normalized = _resource_defaults(policy, layer)
    normalized.update(deepcopy(resource))
    normalized.setdefault("layer", layer.get("id", "unknown"))
    normalized.setdefault("resource_id", resource.get("id") or resource.get("service") or resource.get("fqdn") or resource.get("domain"))
    normalized.setdefault("egress_policy", normalized.get("egress_policy", "proxy"))
    normalized.setdefault("lifecycle", normalized.get("lifecycle", "required"))
    normalized["domains"] = list(dict.fromkeys(_as_list(normalized.get("domains")) + _as_list(normalized.get("fqdn") or normalized.get("domain"))))
    normalized["ipv4_cidrs"] = list(dict.fromkeys(_as_list(normalized.get("ipv4_cidrs"))))
    normalized["ipv6_cidrs"] = list(dict.fromkeys(_as_list(normalized.get("ipv6_cidrs"))))
    if normalized.get("expected_ipv4"):
        normalized["ipv4_cidrs"].append(f"{normalized['expected_ipv4']}/32")
        normalized["ipv4_cidrs"] = list(dict.fromkeys(normalized["ipv4_cidrs"]))
    return normalized


def internet_access_policy_resources(policy: Any, layers: Any = None) -> list[dict[str, Any]]:
    policy_map = _as_mapping(policy, "internet_access_policy")
    selected_layers = [str(layer) for layer in _as_list(layers)]
    include_all = not selected_layers or "all" in selected_layers
    resources: list[dict[str, Any]] = []

    for layer in policy_map.get("layers", []) or []:
        if not isinstance(layer, dict):
            raise AnsibleFilterError("internet_access_policy layers must be mappings")
        layer_id = str(layer.get("id", ""))
        if not layer_id:
            raise AnsibleFilterError("internet_access_policy layer id is required")
        if not include_all and layer_id not in selected_layers:
            continue
        for resource in layer.get("resources", []) or []:
            if not isinstance(resource, dict):
                raise AnsibleFilterError(f"internet_access_policy layer {layer_id} resource must be a mapping")
            resources.append(_normalize_resource(policy_map, layer, resource))
    return resources


def internet_access_policy_proxy_routes(policy: Any, layers: Any = None, outbound_tag: str = "") -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for resource in internet_access_policy_resources(policy, layers):
        if resource.get("egress_policy", "proxy") != "proxy" or resource.get("lifecycle") == "disabled":
            continue
        route = {
            "layer": resource.get("layer"),
            "service": resource.get("resource_id"),
            "domains": resource.get("domains", []),
            "ipv4_cidrs": resource.get("ipv4_cidrs", []),
            "ipv6_cidrs": resource.get("ipv6_cidrs", []),
            "expected_port": resource.get("expected_port"),
            "http_url": resource.get("http_url"),
            "outbound_tag": resource.get("outbound_tag") or outbound_tag,
        }
        if route["domains"]:
            route["fqdn"] = route["domains"][0]
        if resource.get("expected_ipv4"):
            route["expected_ipv4"] = resource["expected_ipv4"]
        routes.append(route)
    return routes


def internet_access_policy_routing_route_ready(route: Any) -> bool:
    if not isinstance(route, dict):
        return False
    domains = _as_list(route.get("domains")) + _as_list(route.get("fqdn"))
    ipv4_cidrs = _as_list(route.get("ipv4_cidrs")) + _as_list(route.get("expected_ipv4"))
    return bool(route.get("outbound_tag")) and bool([item for item in domains + ipv4_cidrs if item])


class FilterModule:
    def filters(self):
        return {
            "internet_access_policy_resources": internet_access_policy_resources,
            "internet_access_policy_proxy_routes": internet_access_policy_proxy_routes,
            "internet_access_policy_routing_route_ready": internet_access_policy_routing_route_ready,
        }
