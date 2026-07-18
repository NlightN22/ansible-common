from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

import yaml


MODULE_PATH = Path(__file__).resolve().parents[1] / "plugins" / "filter" / "openwrt_route_model.py"
FIXTURE_PATH = Path(__file__).resolve().parent / "wireguard_fragment.yml"


def load_module():
    spec = importlib.util.spec_from_file_location("openwrt_route_model", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OpenWrtRouteModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_reports_hub_outside_network_cidr(self) -> None:
        fragment = yaml.safe_load(FIXTURE_PATH.read_text())
        fragment["wireguard_site"]["hub"] = {
            "host": "hub01",
            "address": "198.51.101.1/32",
            "allowed_ips": ["198.51.101.1/32"],
        }

        result = self.module.openwrt_route_control_wireguard_cidr_violations([fragment])

        self.assertEqual(
            result,
            [
                {
                    "site_id": "example_wg",
                    "hub_host": "hub01",
                    "network_cidr": "198.51.100.0/24",
                    "offending_members": [
                        {
                            "member_host": "hub01",
                            "member_role": "hub",
                            "address": "198.51.101.1/32",
                        }
                    ],
                }
            ],
        )

    def test_reports_spokes_outside_network_cidr(self) -> None:
        fragment = yaml.safe_load(FIXTURE_PATH.read_text())
        fragment["wireguard_site"]["spokes"][0]["address"] = "198.51.102.2/32"

        result = self.module.openwrt_route_control_wireguard_cidr_violations([fragment])

        self.assertEqual(
            result,
            [
                {
                    "site_id": "example_wg",
                    "hub_host": "hub01",
                    "network_cidr": "198.51.100.0/24",
                    "offending_members": [
                        {
                            "member_host": "edge01",
                            "member_role": "spoke",
                            "address": "198.51.102.2/32",
                        }
                    ],
                }
            ],
        )

    def test_accepts_members_inside_network_cidr(self) -> None:
        fragment = yaml.safe_load(FIXTURE_PATH.read_text())
        fragment["wireguard_site"]["hub"] = {
            "host": "hub01",
            "address": "198.51.100.1/32",
            "allowed_ips": ["198.51.100.1/32"],
        }
        fragment["wireguard_site"]["spokes"][0]["address"] = "198.51.100.2/32"

        result = self.module.openwrt_route_control_wireguard_cidr_violations([fragment])

        self.assertEqual(result, [])

    def test_wireguard_endpoint_route_intent_can_use_interface_role(self) -> None:
        fragment = yaml.safe_load(FIXTURE_PATH.read_text())
        fragment["wireguard_site"].update(
            {
                "id": "term",
                "interface_name": "wg_term",
                "endpoint": {"host": "203.0.113.10"},
                "preferred_transport": {
                    "type": "public",
                    "interface": "wan",
                    "interface_role": "wan",
                    "route": {"section": "term_wg_endpoint_route"},
                },
            }
        )
        fragment["wireguard_site"]["spokes"][0].update(
            {
                "host": "edge01",
                "platform": "openwrt",
                "active": True,
            }
        )

        result = self.module.openwrt_route_control_declared_state([fragment], "edge01")

        self.assertIn(
            {
                "target": "203.0.113.10",
                "source": "wireguard:term:endpoint",
                "section": "term_wg_endpoint_route",
                "interface_role": "wan",
            },
            result["excluded_routes"],
        )


if __name__ == "__main__":
    unittest.main()
