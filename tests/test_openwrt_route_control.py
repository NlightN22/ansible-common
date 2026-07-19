from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "plugins" / "filter" / "openwrt_route_control.py"


def load_module():
    spec = importlib.util.spec_from_file_location("openwrt_route_control", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OpenWrtRouteControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_pppoe_uplink_routes_are_not_reported_as_drift(self) -> None:
        result = self.module.openwrt_route_control_plan(
            route_stdout="\n".join(
                [
                    "203.0.113.10 via 192.0.2.1 dev pppoe-wan",
                    "203.0.113.11 via 192.0.2.1 dev wan",
                ]
            ),
            rule_stdout="",
            uci_stdout="\n".join(
                [
                    "network.@route[5]=route",
                    "network.@route[5].interface='pppoe-wan'",
                    "network.@route[5].target='203.0.113.10'",
                    "network.@route[6]=route",
                    "network.@route[6].interface='wg0'",
                    "network.@route[6].target='198.51.100.0/24'",
                ]
            ),
        )

        self.assertEqual(result["extra_routes"], [])
        self.assertEqual(result["extra_uci_routes"], [{"target": "198.51.100.0/24", "via": "", "dev": "wg0", "table": "main", "metric": "", "section": "@route[6]"}])
        self.assertEqual(result["cleanup_uci_sections"], ["network.@route[6]"])

    def test_wg0_runtime_route_still_counts_as_drift(self) -> None:
        result = self.module.openwrt_route_control_plan(
            route_stdout="198.51.100.0/24 dev wg0",
            rule_stdout="",
            uci_stdout="",
        )

        self.assertEqual(
            result["extra_routes"],
            [{"target": "198.51.100.0/24", "via": "", "dev": "wg0", "table": "main", "metric": "", "proto": "", "scope": ""}],
        )

    def test_excluded_wan_role_route_matches_concrete_underlay_device(self) -> None:
        result = self.module.openwrt_route_control_plan(
            route_stdout="203.0.113.10 via 192.0.2.129 dev eth1 proto static",
            rule_stdout="",
            uci_stdout="",
            excluded_routes=[
                {
                    "target": "203.0.113.10/32",
                    "interface_role": "wan",
                    "source": "wireguard:term:endpoint",
                }
            ],
        )

        self.assertEqual(result["extra_routes"], [])

    def test_excluded_wan_role_route_does_not_match_tunnel_device(self) -> None:
        result = self.module.openwrt_route_control_plan(
            route_stdout="203.0.113.10 dev wg_term proto static",
            rule_stdout="",
            uci_stdout="",
            excluded_routes=[
                {
                    "target": "203.0.113.10/32",
                    "interface_role": "wan",
                    "source": "wireguard:term:endpoint",
                }
            ],
        )

        self.assertEqual(
            result["extra_routes"],
            [
                {
                    "target": "203.0.113.10",
                    "via": "",
                    "dev": "wg_term",
                    "table": "main",
                    "metric": "",
                    "proto": "static",
                    "scope": "",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
