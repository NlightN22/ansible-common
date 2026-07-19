from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "plugins" / "module_utils" / "xp2p_model.py"


def load_module():
    spec = importlib.util.spec_from_file_location("xp2p_model", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def redirect_cidrs(view):
    return {redirect["cidr"] for redirect in view["managed_redirects"]}


def server_redirects_by_cidr(view):
    return {redirect["cidr"]: redirect for redirect in view["managed_server_redirects"]}


class XP2PModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.model = {
            "nodes": {},
            "networks": {
                "relay-a": {
                    "id": "relay-a",
                    "type": "xp2p",
                    "hub": "relay-a.example.test",
                    "server": "relay-a.example.test",
                    "endpoint_name": "relay-a-example-test",
                    "endpoint_port": 443,
                    "outbound_tag": "proxy-relay-a-example-test",
                    "source": {
                        "id": "relay-a",
                        "endpoint_name": "relay-a-example-test",
                        "wireguard_transport_site_ids": ["site-a", "site-b"],
                    },
                    "peers": {
                        "edge-a": {
                            "host": "edge-a",
                            "user": "edge-a",
                        },
                        "edge-b": {
                            "host": "edge-b",
                            "user": "edge-b",
                        },
                        "directory-a": {
                            "host": "directory-a",
                            "user": "directory-a",
                        },
                    },
                },
                "site-a": {
                    "id": "site-a",
                    "type": "wireguard",
                    "hub": "edge-a",
                    "hub_host": "edge-a",
                    "preferred_transport": {
                        "type": "xp2p",
                        "star": "relay-a",
                        "routed_cidrs": ["203.0.113.150/32"],
                    },
                },
                "site-b": {
                    "id": "site-b",
                    "type": "wireguard",
                    "hub": "directory-a",
                    "hub_host": "directory-a",
                    "preferred_transport": {
                        "type": "xp2p",
                        "star": "relay-a",
                        "routed_cidrs": ["198.51.100.189/32"],
                    },
                },
            },
        }

    def test_non_hub_clients_route_wireguard_endpoint_through_xp2p(self) -> None:
        view = self.module.architecture_xp2p_view(self.model, "relay-a", "edge-b")

        self.assertEqual(
            redirect_cidrs(view),
            {"203.0.113.150/32", "198.51.100.189/32"},
        )

    def test_wireguard_hub_does_not_route_own_public_endpoint_through_xp2p(self) -> None:
        view = self.module.architecture_xp2p_view(self.model, "relay-a", "edge-a")

        self.assertEqual(redirect_cidrs(view), {"198.51.100.189/32"})

    def test_server_reverse_redirect_points_wireguard_endpoint_to_hub_client(self) -> None:
        view = self.module.architecture_xp2p_view(self.model, "relay-a", "relay-a.example.test")

        redirects = server_redirects_by_cidr(view)
        self.assertEqual(
            redirects["203.0.113.150/32"],
            {
                "cidr": "203.0.113.150/32",
                "host": "relay-a-example-test",
                "tag": "edge-arelay-a-example-test.rev",
            },
        )

    def test_client_endpoint_intents_include_xp2p_and_three_x_ui_sources(self) -> None:
        architecture_model = {
            "networks": {
                "relay-a": self.model["networks"]["relay-a"],
                "overlay-a": {
                    "id": "overlay-a",
                    "type": "xray_overlay",
                    "hub": "overlay-a.example.test",
                    "source": {
                        "id": "overlay-a",
                        "panel": {"protocol": "trojan"},
                        "endpoint": {
                            "host": "overlay-a.example.test",
                            "port": 443,
                            "sni": "overlay-a.example.test",
                        },
                    },
                    "peers": {
                        "edge-a": {
                            "host": "edge-a",
                            "email": "edge-a",
                            "state": "present",
                        },
                    },
                },
            },
        }

        intents = self.module.xp2p_client_endpoint_intents(architecture_model, "edge-a")

        self.assertEqual(
            {intent["source"]: intent["tag"] for intent in intents},
            {
                "xp2p:relay-a": "proxy-relay-a-example-test",
                "three_x_ui:overlay-a": "proxy-overlay-a-example-test",
            },
        )
        self.assertEqual(
            self.module.xp2p_client_endpoint_tags(intents),
            ["proxy-overlay-a-example-test", "proxy-relay-a-example-test"],
        )

    def test_single_source_apply_role_preserves_sibling_endpoints(self) -> None:
        role_path = MODULE_PATH.parents[2] / "roles" / "xp2p_client_endpoints" / "tasks" / "apply.yml"
        apply_tasks = role_path.read_text(encoding="utf-8")

        self.assertNotIn("xp2p client install --force", apply_tasks)
        self.assertNotIn("xp2p client remove --all", apply_tasks)
        self.assertNotIn("--force", apply_tasks)
        self.assertNotIn("--all", apply_tasks)
        self.assertIn("xp2p client remove '{{ item.item.tag }}' --quiet", apply_tasks)


if __name__ == "__main__":
    unittest.main()
