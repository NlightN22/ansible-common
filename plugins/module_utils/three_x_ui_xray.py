from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import requests
import urllib3


API_ROUTE = {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}


class ThreeXUIError(RuntimeError):
    pass


class ThreeXUIXrayClient:
    def __init__(
        self,
        panel_url: str,
        username: str,
        password: str,
        verify_tls: bool,
        timeout: int,
    ) -> None:
        self.panel_url = panel_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self._csrf_token: str | None = None
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def login(self) -> None:
        data = self._json(
            self.session.post(
                f"{self.panel_url}/login",
                data={"username": self.username, "password": self.password},
                verify=self.verify_tls,
                timeout=self.timeout,
            ),
            "login",
        )
        if not data.get("success"):
            raise ThreeXUIError(f"3x-ui login failed: {data.get('msg', 'unknown error')}")

    def get_xray_config(self) -> dict[str, Any]:
        data = self._request_json("POST", "/panel/xray/", csrf=True)
        if not data.get("success"):
            raise ThreeXUIError(f"failed to get xray config: {data.get('msg', 'unknown error')}")
        try:
            panel_config = json.loads(data.get("obj") or "{}")
            setting = panel_config.get("xraySetting")
            if isinstance(setting, str):
                return json.loads(setting)
            if isinstance(setting, dict):
                return setting
        except ValueError as exc:
            raise ThreeXUIError("3x-ui API returned invalid xray config JSON") from exc
        raise ThreeXUIError("3x-ui API response does not contain xraySetting")

    def save_xray_config(self, config: dict[str, Any], restart: bool) -> None:
        data = self._request_json(
            "POST",
            "/panel/xray/update",
            form_body={
                "xraySetting": json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                "outboundTestUrl": "https://www.google.com/generate_204",
            },
            csrf=True,
        )
        if not data.get("success"):
            raise ThreeXUIError(f"failed to save xray config: {data.get('msg', 'unknown error')}")
        if restart:
            data = self._request_json("POST", "/panel/api/server/restartXrayService", csrf=True)
            if not data.get("success"):
                raise ThreeXUIError(f"failed to restart xray: {data.get('msg', 'unknown error')}")

    def _request_json(
        self,
        method: str,
        path: str,
        form_body: dict[str, Any] | None = None,
        csrf: bool = False,
    ) -> dict[str, Any]:
        csrf_token = self._csrf() if csrf else ""
        headers = {"X-CSRF-Token": csrf_token} if csrf_token else None
        return self._json(
            self.session.request(
                method,
                f"{self.panel_url}{path}",
                data=form_body,
                headers=headers,
                verify=self.verify_tls,
                timeout=self.timeout,
            ),
            path,
        )

    def _csrf(self) -> str:
        if self._csrf_token is not None:
            return self._csrf_token
        response = self.session.get(
            f"{self.panel_url}/panel/csrf-token",
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        if response.status_code == 404:
            self._csrf_token = ""
            return self._csrf_token
        data = self._json(response, "/panel/csrf-token")
        self._csrf_token = str(data.get("obj") or "")
        return self._csrf_token

    @staticmethod
    def _json(response: requests.Response, operation: str) -> dict[str, Any]:
        try:
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            raise ThreeXUIError(f"3x-ui API request failed during {operation}: {exc}") from exc
        except ValueError as exc:
            raise ThreeXUIError(f"3x-ui API returned non-JSON response during {operation}") from exc


def reconcile_xray_config(config: dict[str, Any], spec: dict[str, Any]) -> dict[str, int]:
    result = {
        "inbounds_added": 0,
        "inbounds_updated": 0,
        "inbounds_deleted": 0,
        "portals_added": 0,
        "portals_deleted": 0,
        "routes_added": 0,
        "routes_deleted": 0,
    }
    for inbound in spec.get("inbounds", []):
        action = reconcile_inbound(config, inbound)
        if action:
            result[f"inbounds_{action}"] += 1
    for portal in spec.get("reverse_portals", []):
        result["portals_added"] += int(add_reverse_portal(config, portal))
    for route in spec.get("routes", []):
        result["routes_added"] += int(add_route(config, route))
    validate_api_route(config)
    return result


def reconcile_inbound(config: dict[str, Any], desired: dict[str, Any]) -> str:
    if desired.get("state", "present") != "present":
        return ""
    normalized = normalize_inbound(desired)
    inbounds = ensure_list(config, "inbounds")
    tag_indexes = [index for index, item in enumerate(inbounds) if item.get("tag") == normalized["tag"]]
    if tag_indexes:
        keep = tag_indexes[0]
        changed = inbounds[keep] != normalized or len(tag_indexes) > 1
        inbounds[keep] = normalized
        config["inbounds"] = [item for index, item in enumerate(inbounds) if index == keep or index not in tag_indexes]
        return "updated" if changed else ""
    adopt = find_adoptable_inbound(inbounds, normalized) if desired.get("adopt_existing", False) else None
    if adopt is not None:
        changed = inbounds[adopt] != normalized
        inbounds[adopt] = normalized
        return "updated" if changed else ""
    inbounds.append(normalized)
    return "added"


def normalize_inbound(inbound: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "listen": inbound.get("listen") or inbound.get("bind_host") or "127.0.0.1",
        "port": int(inbound["port"]),
        "protocol": inbound.get("protocol", "socks"),
        "settings": deepcopy(inbound.get("settings", {})),
        "tag": inbound["tag"],
    }
    for key in ("sniffing", "allocate"):
        if key in inbound:
            normalized[key] = deepcopy(inbound[key])
    return normalized


def find_adoptable_inbound(inbounds: list[dict[str, Any]], desired: dict[str, Any]) -> int | None:
    loopback_matches = [
        index
        for index, inbound in enumerate(inbounds)
        if inbound.get("protocol") == desired.get("protocol")
        and inbound.get("listen", "") in {"127.0.0.1", "localhost"}
    ]
    return loopback_matches[0] if len(loopback_matches) == 1 else None


def add_reverse_portal(config: dict[str, Any], portal: dict[str, Any]) -> bool:
    if portal.get("state", "present") != "present":
        return False
    portals = config.setdefault("reverse", {}).setdefault("portals", [])
    normalized = {"tag": portal["tag"], "domain": portal["domain"]}
    for index, item in enumerate(portals):
        if item.get("tag") == normalized["tag"]:
            if item == normalized:
                return False
            portals[index] = normalized
            return True
    portals.append(normalized)
    return True


def add_route(config: dict[str, Any], route: dict[str, Any]) -> bool:
    if route.get("state", "present") != "present":
        return False
    rules = config.setdefault("routing", {}).setdefault("rules", [])
    normalized = normalize_route({key: value for key, value in route.items() if key != "state"})
    equivalent_indexes = [
        index for index, rule in enumerate(rules) if route_identity(rule) == route_identity(normalized)
    ]
    if equivalent_indexes:
        keep = equivalent_indexes[0]
        changed = rules[keep] != normalized or len(equivalent_indexes) > 1
        rules[keep] = normalized
        config["routing"]["rules"] = [
            rule for index, rule in enumerate(rules) if index == keep or index not in equivalent_indexes
        ]
        return changed
    rules.insert(first_non_service_index(rules), normalized)
    return True


def normalize_route(route: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(route)
    normalized.setdefault("type", "field")
    for key in ("domain", "ip", "inboundTag"):
        if isinstance(normalized.get(key), str):
            normalized[key] = [normalized[key]]
    return normalized


def route_identity(route: dict[str, Any]) -> tuple[object, ...]:
    normalized = normalize_route(route)
    if "ip" in normalized:
        return (
            normalized.get("type", "field"),
            "ip",
            tuple(normalized.get("ip") or []),
            normalized.get("outboundTag"),
        )
    if "domain" in normalized:
        return (
            normalized.get("type", "field"),
            "domain",
            tuple(normalized.get("domain") or []),
            normalized.get("outboundTag"),
            tuple(normalized.get("inboundTag") or []),
        )
    return tuple(sorted((key, json.dumps(value, sort_keys=True)) for key, value in normalized.items()))


def first_non_service_index(rules: list[dict[str, Any]]) -> int:
    indexes = [index for index, rule in enumerate(rules) if rule == API_ROUTE or rule.get("outboundTag") == "dns-out"]
    return indexes[-1] + 1 if indexes else 0


def validate_api_route(config: dict[str, Any]) -> None:
    rules = config.setdefault("routing", {}).setdefault("rules", [])
    if not any(rule == API_ROUTE for rule in rules):
        raise ThreeXUIError("xray config is missing the 3x-ui API routing rule")


def ensure_list(config: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = config.setdefault(key, [])
    if not isinstance(value, list):
        raise ThreeXUIError(f"xray config .{key} must be a list")
    return value


def write_backup(path: str, config: dict[str, Any]) -> None:
    backup_path = Path(path)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path.write_text(json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
