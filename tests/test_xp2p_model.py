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


def simulated_endpoint_apply_commands(module, intents, current_output):
    plan = module.xp2p_client_endpoint_apply_plan(intents, current_output)
    if plan["implicit_replacements"]:
        return [f"assert replace=true for {item}" for item in plan["implicit_replacements"]]
    commands = []
    commands.extend([f"xp2p client remove {item['tag']} --quiet" for item in plan["absent"]])
    commands.extend([f"xp2p client install {item['tag']}" for item in plan["missing"]])
    for item in plan["replacements"]:
        commands.append(f"xp2p client remove {item['tag']} --quiet")
        commands.append(f"xp2p client install {item['tag']}")
    return commands


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
            next(intent for intent in intents if intent["source"] == "three_x_ui:overlay-a")["heartbeat_mode"],
            "auto",
        )
        self.assertFalse(next(intent for intent in intents if intent["source"] == "three_x_ui:overlay-a")["allow_insecure"])
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
        self.assertIn("xp2p client remove '{{ item.tag }}' --quiet", apply_tasks)

    def test_endpoint_apply_plan_preserves_sibling_endpoint_tags(self) -> None:
        intents = [
            {
                "tag": "proxy-dcpkt2-ddns-net",
                "source": "three_x_ui:dcpkt2-openwrt",
                "state": "present",
                "user": "AB-Zavodskaya",
            },
            {
                "tag": "proxy-ex4-komponent-m-ru",
                "source": "three_x_ui:ex4-openwrt",
                "state": "present",
                "user": "AB-Zavodskaya",
            },
            {
                "tag": "proxy-in1-komponent-m-ru",
                "source": "xp2p:in1",
                "state": "present",
                "user": "AB-Zavodskaya",
            },
        ]
        current = "\n".join(
            [
                "proxy-ex4-komponent-m-ru AB-Zavodskaya",
                "proxy-in1-komponent-m-ru AB-Zavodskaya",
            ]
        )

        plan = self.module.xp2p_client_endpoint_apply_plan([intents[0]], current)

        self.assertEqual([item["tag"] for item in plan["missing"]], ["proxy-dcpkt2-ddns-net"])
        self.assertEqual(plan["absent"], [])
        self.assertEqual(plan["replacements"], [])
        self.assertEqual(plan["implicit_replacements"], [])

    def test_client_endpoint_records_parse_table_and_rendered_config_outputs(self) -> None:
        table_output = "\n".join(
            [
                "dcpkt2.ddns.net     proxy-dcpkt2-ddns-net     109.71.242.190   443   AB-Zavodskaya  false           dcpkt2.ddns.net",
                "in1.komponent-m.ru  proxy-in1-komponent-m-ru  185.177.216.114  443   AB-Zavodskaya  false           in1.komponent-m.ru",
            ]
        )
        rendered_config_output = (
            'endpoints = [{ address = "109.71.242.190", hostname = "dcpkt2.ddns.net", '
            'port = 443, server_name = "dcpkt2.ddns.net", tag = "proxy-dcpkt2-ddns-net", '
            'user = "AB-Zavodskaya" }]'
        )

        table_records = self.module.xp2p_client_endpoint_records(table_output)
        rendered_records = self.module.xp2p_client_endpoint_records(rendered_config_output)

        self.assertEqual(
            {(record["tag"], record["user"]) for record in table_records},
            {
                ("proxy-dcpkt2-ddns-net", "AB-Zavodskaya"),
                ("proxy-in1-komponent-m-ru", "AB-Zavodskaya"),
            },
        )
        self.assertEqual(rendered_records[0]["tag"], "proxy-dcpkt2-ddns-net")
        self.assertEqual(rendered_records[0]["port"], "443")
        self.assertEqual(rendered_records[0]["user"], "AB-Zavodskaya")

    def test_single_source_apply_command_simulation_preserves_live_siblings(self) -> None:
        intent = {
            "tag": "proxy-dcpkt2-ddns-net",
            "source": "three_x_ui:dcpkt2-openwrt",
            "state": "present",
            "user": "AB-Zavodskaya",
        }
        current = "\n".join(
            [
                "in1.komponent-m.ru  proxy-in1-komponent-m-ru  185.177.216.114  443  AB-Zavodskaya  false  in1.komponent-m.ru",
                "ex4.komponent-m.ru  proxy-ex4-komponent-m-ru  141.105.64.152   443  AB-Zavodskaya  false  ex4.komponent-m.ru",
            ]
        )

        commands = simulated_endpoint_apply_commands(self.module, [intent], current)

        self.assertEqual(commands, ["xp2p client install proxy-dcpkt2-ddns-net"])
        self.assertFalse(any("proxy-in1-komponent-m-ru" in command for command in commands))
        self.assertFalse(any("proxy-ex4-komponent-m-ru" in command for command in commands))

    def test_endpoint_apply_plan_requires_explicit_replacement(self) -> None:
        intent = {
            "tag": "proxy-dcpkt2-ddns-net",
            "source": "three_x_ui:dcpkt2-openwrt",
            "state": "present",
            "user": "AB-Zavodskaya",
        }
        current = "proxy-dcpkt2-ddns-net OLD-CLIENT"

        plan = self.module.xp2p_client_endpoint_apply_plan([intent], current)

        self.assertEqual(plan["missing"], [])
        self.assertEqual(plan["replacements"], [])
        self.assertEqual(plan["implicit_replacements"], ["three_x_ui:dcpkt2-openwrt proxy-dcpkt2-ddns-net"])

    def test_endpoint_apply_plan_allows_explicit_replacement(self) -> None:
        intent = {
            "tag": "proxy-dcpkt2-ddns-net",
            "source": "three_x_ui:dcpkt2-openwrt",
            "state": "present",
            "user": "AB-Zavodskaya",
            "replace": True,
        }
        current = "proxy-dcpkt2-ddns-net OLD-CLIENT"

        plan = self.module.xp2p_client_endpoint_apply_plan([intent], current)

        self.assertEqual([item["tag"] for item in plan["replacements"]], ["proxy-dcpkt2-ddns-net"])
        self.assertEqual(plan["missing"], [])
        self.assertEqual(plan["implicit_replacements"], [])


if __name__ == "__main__":
    unittest.main()
