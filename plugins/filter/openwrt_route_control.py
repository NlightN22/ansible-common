"""OpenWrt route/rule audit helpers."""

from __future__ import annotations

from ipaddress import IPv4Network
from shlex import split as shell_split
from typing import Any

from ansible.errors import AnsibleFilterError


SYSTEM_RULE_PRIORITIES = {"0", "32766", "32767"}
EXTERNAL_UPLINK_INTERFACES = {"wan", "wan6"}
EXTERNAL_UPLINK_PREFIXES = ("pppoe-",)


def _items(value: Any, name: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AnsibleFilterError(f"{name} must be a list")
    return [item for item in value if isinstance(item, dict)]


def _text(value: Any) -> str:
    return "" if value is None else str(value)

def _clean(value: Any) -> str:
    return _text(value).strip().strip("'\"")

def _table(value: Any) -> str:
    value = _clean(value)
    return value or "main"


def _rule_scope(value: Any) -> str:
    value = _clean(value)
    return "" if value in {"", "all", "0.0.0.0/0"} else value


def _fwmark(value: Any) -> str:
    value = _clean(value)
    return value.removesuffix("/0xffffffff")


def _target(value: Any) -> str:
    value = _clean(value)
    if value == "0.0.0.0/0":
        return "default"
    if value.endswith("/32"):
        return value[:-3]
    return value


def _netmask_to_prefix(netmask: str) -> int | None:
    if not netmask:
        return None
    try:
        return IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except ValueError:
        return None


def _uci_target(target: str, netmask: str = "") -> str:
    target = _target(target)
    if target == "default" or "/" in target:
        return target
    prefix = _netmask_to_prefix(netmask)
    return f"{target}/{prefix}" if prefix is not None and prefix != 32 else target


def _canonical_route(route: dict[str, Any]) -> dict[str, str]:
    canonical = {
        "target": _target(route.get("target") or route.get("destination") or route.get("dest")),
        "via": _clean(route.get("via") or route.get("gateway")),
        "dev": _clean(route.get("dev") or route.get("interface")),
        "table": _table(route.get("table")),
        "metric": _clean(route.get("metric")),
    }
    for field in ("source", "section", "owner"):
        if route.get(field):
            canonical[field] = _clean(route[field])
    return canonical


def _canonical_rule(rule: dict[str, Any]) -> dict[str, str]:
    canonical = {
        "priority": _clean(rule.get("priority") or rule.get("pref")),
        "from": _rule_scope(rule.get("from") or rule.get("src")),
        "to": _rule_scope(rule.get("to") or rule.get("dest")),
        "fwmark": _fwmark(rule.get("fwmark") or rule.get("mark")),
        "iif": _clean(rule.get("iif") or rule.get("in")),
        "oif": _clean(rule.get("oif") or rule.get("out")),
        "lookup": _table(rule.get("lookup") or rule.get("table")),
    }
    for field in ("source", "section", "owner"):
        if rule.get(field):
            canonical[field] = _clean(rule[field])
    return canonical


def _route_key(route: dict[str, str]) -> tuple[str, str, str, str, str]:
    return (route["table"], route["target"], route["via"], route["dev"], route["metric"])


def _rule_key(rule: dict[str, str]) -> tuple[str, str, str, str, str, str, str]:
    return (
        rule["priority"],
        rule["from"],
        rule["to"],
        rule["fwmark"],
        rule["iif"],
        rule["oif"],
        rule["lookup"],
    )


def _parse_route_line(line: str) -> dict[str, str]:
    tokens = shell_split(line)
    if not tokens:
        return {}
    route = {"target": _target(tokens[0]), "table": "main", "via": "", "dev": "", "metric": "", "proto": "", "scope": ""}
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"via", "dev", "table", "metric", "proto", "scope", "src"} and index + 1 < len(tokens):
            route[token] = tokens[index + 1]
            index += 2
        else:
            index += 1
    return route


def _parse_rule_line(line: str) -> dict[str, str]:
    if ":" not in line:
        return {}
    priority, body = line.split(":", 1)
    tokens = shell_split(body.strip())
    rule = {"priority": priority.strip(), "from": "", "to": "", "fwmark": "", "iif": "", "oif": "", "lookup": ""}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"from", "to", "fwmark", "iif", "oif", "lookup"} and index + 1 < len(tokens):
            rule[token] = tokens[index + 1]
            index += 2
        elif token == "table" and index + 1 < len(tokens):
            rule["lookup"] = tokens[index + 1]
            index += 2
        else:
            index += 1
        rule["lookup"] = _table(rule["lookup"])
    return rule


def _uci_sections(uci_stdout: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    for raw_line in uci_stdout.splitlines():
        line = raw_line.strip()
        if not line.startswith("network.") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parts = key.split(".")
        if len(parts) == 2:
            sections.setdefault(parts[1], {})["type"] = _clean(value)
        elif len(parts) >= 3:
            sections.setdefault(parts[1], {})[parts[2]] = _clean(value)
    return sections


def _parse_uci_routes(uci_stdout: str) -> list[dict[str, str]]:
    routes = []
    for section, data in _uci_sections(uci_stdout).items():
        if data.get("type") != "route" or data.get("disabled") == "1":
            continue
        routes.append(
            {
                "section": section,
                "target": _uci_target(data.get("target", "default"), data.get("netmask", "")),
                "via": data.get("gateway", ""),
                "dev": data.get("interface", ""),
                "table": _table(data.get("table")),
                "metric": data.get("metric", ""),
            }
        )
    return routes


def _parse_uci_rules(uci_stdout: str) -> list[dict[str, str]]:
    rules = []
    for section, data in _uci_sections(uci_stdout).items():
        if data.get("type") != "rule" or data.get("disabled") == "1":
            continue
        rules.append(
            {
                "section": section,
                "priority": data.get("priority", ""),
                "from": data.get("src", ""),
                "to": data.get("dest", ""),
                "fwmark": data.get("mark", ""),
                "iif": data.get("in", ""),
                "oif": data.get("out", ""),
                "lookup": _table(data.get("lookup") or data.get("table")),
            }
        )
    return rules


def _route_delete_command(route: dict[str, str]) -> str:
    parts = ["ip", "route", "del", route["target"]]
    if route["table"] != "main":
        parts += ["table", route["table"]]
    if route["via"]:
        parts += ["via", route["via"]]
    if route["dev"]:
        parts += ["dev", route["dev"]]
    if route["metric"]:
        parts += ["metric", route["metric"]]
    return " ".join(parts)


def _route_replace_command(route: dict[str, str]) -> str:
    parts = ["ip", "route", "replace", route["target"]]
    if route["table"] != "main":
        parts += ["table", route["table"]]
    if route["via"]:
        parts += ["via", route["via"]]
    if route["dev"]:
        parts += ["dev", route["dev"]]
    if route["metric"]:
        parts += ["metric", route["metric"]]
    return " ".join(parts)


def _rule_delete_command(rule: dict[str, str]) -> str:
    parts = ["ip", "rule", "del"]
    if rule["priority"]:
        parts += ["priority", rule["priority"]]
    for field in ("from", "to", "fwmark", "iif", "oif"):
        if rule[field]:
            parts += [field, rule[field]]
    if rule["lookup"]:
        parts += ["lookup", rule["lookup"]]
    return " ".join(parts)


def _rule_add_command(rule: dict[str, str]) -> str:
    parts = ["ip", "rule", "add"]
    if rule["priority"]:
        parts += ["priority", rule["priority"]]
    for field in ("from", "to", "fwmark", "iif", "oif"):
        if rule[field]:
            parts += [field, rule[field]]
    if rule["lookup"]:
        parts += ["lookup", rule["lookup"]]
    return " ".join(parts)


def _is_safe_extra_route(route: dict[str, str]) -> bool:
    if (route["target"] == "default" and route["table"] == "main") or route["table"] in {"local", "255"}:
        return False
    if _is_external_uplink_interface(route["dev"]):
        return False
    proto = route.get("proto", "")
    scope = route.get("scope", "")
    return not (proto == "kernel" or scope == "link")


def _is_external_uplink_interface(interface: str) -> bool:
    interface = _clean(interface)
    return interface in EXTERNAL_UPLINK_INTERFACES or any(
        interface.startswith(prefix) for prefix in EXTERNAL_UPLINK_PREFIXES
    )


def _is_safe_extra_rule(rule: dict[str, str]) -> bool:
    return rule["priority"] not in SYSTEM_RULE_PRIORITIES


def _changed_routes(declared: list[dict[str, str]], runtime: list[dict[str, str]]) -> list[dict[str, dict[str, str]]]:
    changes = []
    for expected in declared:
        for actual in runtime:
            same_route = expected["table"] == actual["table"] and expected["target"] == actual["target"]
            if same_route and _route_key(expected) != _route_key(actual):
                changes.append({"expected": expected, "actual": actual})
    return changes


def _changed_rules(declared: list[dict[str, str]], runtime: list[dict[str, str]]) -> list[dict[str, dict[str, str]]]:
    changes = []
    for expected in declared:
        for actual in runtime:
            if expected["priority"] and expected["priority"] == actual["priority"] and _rule_key(expected) != _rule_key(actual):
                changes.append({"expected": expected, "actual": actual})
    return changes


def openwrt_route_control_plan(
    route_stdout: str,
    rule_stdout: str,
    uci_stdout: str,
    declared_routes: Any = None,
    declared_rules: Any = None,
    excluded_routes: Any = None,
    excluded_rules: Any = None,
) -> dict[str, Any]:
    declared_route_items = [_canonical_route(item) for item in _items(declared_routes, "declared_routes")]
    declared_rule_items = [_canonical_rule(item) for item in _items(declared_rules, "declared_rules")]
    excluded_route_keys = {_route_key(_canonical_route(item)) for item in _items(excluded_routes, "excluded_routes")}
    excluded_rule_keys = {_rule_key(_canonical_rule(item)) for item in _items(excluded_rules, "excluded_rules")}

    runtime_routes = [_parse_route_line(line) for line in route_stdout.splitlines()]
    runtime_routes = [_canonical_route(route) | {k: route.get(k, "") for k in ("proto", "scope")} for route in runtime_routes if route]
    runtime_rules = [_parse_rule_line(line) for line in rule_stdout.splitlines()]
    runtime_rules = [_canonical_rule(rule) for rule in runtime_rules if rule]
    uci_routes = [_canonical_route(route) | {"section": route["section"]} for route in _parse_uci_routes(uci_stdout)]
    uci_rules = [_canonical_rule(rule) | {"section": rule["section"]} for rule in _parse_uci_rules(uci_stdout)]

    declared_route_keys = {_route_key(route) for route in declared_route_items}
    declared_rule_keys = {_rule_key(rule) for rule in declared_rule_items}
    runtime_route_keys = {_route_key(route) for route in runtime_routes}
    runtime_rule_keys = {_rule_key(rule) for rule in runtime_rules}

    extra_routes = [
        route for route in runtime_routes
        if _route_key(route) not in declared_route_keys
        and _route_key(route) not in excluded_route_keys
        and _is_safe_extra_route(route)
    ]
    extra_rules = [
        rule for rule in runtime_rules
        if _rule_key(rule) not in declared_rule_keys
        and _rule_key(rule) not in excluded_rule_keys
        and _is_safe_extra_rule(rule)
    ]
    extra_uci_routes = [
        route for route in uci_routes
        if _route_key(route) not in declared_route_keys
        and _route_key(route) not in excluded_route_keys
        and _is_safe_extra_route(route)
    ]
    extra_uci_rules = [
        rule for rule in uci_rules
        if _rule_key(rule) not in declared_rule_keys and _rule_key(rule) not in excluded_rule_keys
    ]
    missing_routes = [route for route in declared_route_items if _route_key(route) not in runtime_route_keys]
    missing_rules = [rule for rule in declared_rule_items if _rule_key(rule) not in runtime_rule_keys]
    changed_routes = _changed_routes(declared_route_items, runtime_routes)
    changed_rules = _changed_rules(declared_rule_items, runtime_rules)

    return {
        "declared_routes": declared_route_items,
        "declared_rules": declared_rule_items,
        "runtime_routes": runtime_routes,
        "runtime_rules": runtime_rules,
        "uci_routes": uci_routes,
        "uci_rules": uci_rules,
        "missing_routes": missing_routes,
        "missing_rules": missing_rules,
        "changed_routes": changed_routes,
        "changed_rules": changed_rules,
        "extra_routes": extra_routes,
        "extra_rules": extra_rules,
        "extra_uci_routes": extra_uci_routes,
        "extra_uci_rules": extra_uci_rules,
        "cleanup_route_commands": [_route_delete_command(route) for route in extra_routes],
        "cleanup_rule_commands": [_rule_delete_command(rule) for rule in extra_rules],
        "apply_route_commands": [_route_replace_command(route) for route in missing_routes],
        "apply_rule_commands": [_rule_add_command(rule) for rule in missing_rules],
        "cleanup_uci_sections": [f"network.{item['section']}" for item in extra_uci_routes + extra_uci_rules],
        "changed": bool(
            missing_routes or missing_rules or changed_routes or changed_rules
            or extra_routes or extra_rules or extra_uci_routes or extra_uci_rules
        ),
    }


def _collect_section(stdout: str, start_marker: str, end_marker: str | None = None) -> str:
    start = stdout.find(start_marker)
    if start < 0:
        return ""
    start += len(start_marker)
    if start < len(stdout) and stdout[start] == "\n":
        start += 1
    end = stdout.find(end_marker, start) if end_marker else -1
    return stdout[start:end if end >= 0 else len(stdout)]


def openwrt_route_control_plan_from_collect(
    collect_stdout: str,
    declared_routes: Any = None,
    declared_rules: Any = None,
    excluded_routes: Any = None,
    excluded_rules: Any = None,
) -> dict[str, Any]:
    return openwrt_route_control_plan(
        _collect_section(collect_stdout, "### ip route show table all", "### ip rule show"),
        _collect_section(collect_stdout, "### ip rule show", "### uci show network"),
        _collect_section(collect_stdout, "### uci show network"),
        declared_routes,
        declared_rules,
        excluded_routes,
        excluded_rules,
    )


class FilterModule:
    def filters(self):
        return {
            "openwrt_route_control_plan": openwrt_route_control_plan,
            "openwrt_route_control_plan_from_collect": openwrt_route_control_plan_from_collect,
        }
