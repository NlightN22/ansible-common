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
                    "45.137.190.126 via 91.219.99.1 dev pppoe-wan",
                    "1.1.1.1 via 91.219.99.1 dev wan",
                ]
            ),
            rule_stdout="",
            uci_stdout="\n".join(
                [
                    "network.@route[5]=route",
                    "network.@route[5].interface='pppoe-wan'",
                    "network.@route[5].target='45.137.190.126'",
                    "network.@route[6]=route",
                    "network.@route[6].interface='wg0'",
                    "network.@route[6].target='10.50.10.0/24'",
                ]
            ),
        )

        self.assertEqual(result["extra_routes"], [])
        self.assertEqual(result["extra_uci_routes"], [{"target": "10.50.10.0/24", "via": "", "dev": "wg0", "table": "main", "metric": "", "section": "@route[6]"}])
        self.assertEqual(result["cleanup_uci_sections"], ["network.@route[6]"])

    def test_wg0_runtime_route_still_counts_as_drift(self) -> None:
        result = self.module.openwrt_route_control_plan(
            route_stdout="10.50.10.0/24 dev wg0",
            rule_stdout="",
            uci_stdout="",
        )

        self.assertEqual(
            result["extra_routes"],
            [{"target": "10.50.10.0/24", "via": "", "dev": "wg0", "table": "main", "metric": "", "proto": "", "scope": ""}],
        )


if __name__ == "__main__":
    unittest.main()
