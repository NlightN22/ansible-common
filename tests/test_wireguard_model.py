from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

import yaml


MODULE_PATH = Path(__file__).resolve().parents[1] / "plugins" / "filter" / "model.py"
WIREGUARD_MODULE_PATH = Path(__file__).resolve().parents[1] / "plugins" / "filter" / "wireguard.py"
FIXTURE_PATH = Path(__file__).resolve().parent / "wireguard_fragment.yml"
COLLECTIONS_PATH = Path(__file__).resolve().parents[2] / "infra-ansible" / "collections"

if str(COLLECTIONS_PATH) not in sys.path:
    sys.path.insert(0, str(COLLECTIONS_PATH))


def load_module():
    spec = importlib.util.spec_from_file_location("model", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_wireguard_module():
    spec = importlib.util.spec_from_file_location("wireguard", WIREGUARD_MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {WIREGUARD_MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WireGuardModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.wireguard_module = load_wireguard_module()

    def test_wireguard_hub_allowed_ips_do_not_inherit_to_peers(self) -> None:
        fragment = yaml.safe_load(FIXTURE_PATH.read_text())
        fragment["wireguard_site"]["hub"]["allowed_ips"] = ["198.51.100.1/32"]

        normalized = self.module.architecture_model_from_fragments([fragment])
        normalized = self.module.architecture_normalize(normalized)
        resolved = self.module.architecture_wireguard_view(normalized, "example_wg", "edge01")

        self.assertEqual(resolved["hub_allowed_ips"], ["198.51.100.1/32"])
        self.assertIsNone(resolved["active_peers"]["edge01"].get("allowed_ips"))

    def test_wireguard_expected_peers_keep_peer_only_allowed_ips(self) -> None:
        fragment = yaml.safe_load(FIXTURE_PATH.read_text())
        fragment["wireguard_site"]["hub"]["allowed_ips"] = ["198.51.100.1/32"]

        normalized = self.module.architecture_model_from_fragments([fragment])
        normalized = self.module.architecture_normalize(normalized)
        resolved = self.module.architecture_wireguard_view(normalized, "example_wg", "hub01")
        peers = self.wireguard_module.wireguard_expected_peers(resolved)

        self.assertEqual(peers[0]["allowed_ips"], ["198.51.100.2/32"])

    def test_wireguard_expected_peers_keep_hub_allowed_ips_on_spoke_views(self) -> None:
        fragment = yaml.safe_load(FIXTURE_PATH.read_text())
        fragment["wireguard_site"]["hub"]["allowed_ips"] = ["198.51.100.1/32"]

        normalized = self.module.architecture_model_from_fragments([fragment])
        normalized = self.module.architecture_normalize(normalized)
        resolved = self.module.architecture_wireguard_view(normalized, "example_wg", "edge01")
        peers = self.wireguard_module.wireguard_expected_peers(resolved)

        self.assertEqual(peers[0]["allowed_ips"], ["198.51.100.1/32"])

    def test_three_x_ui_star_can_use_hub_host_as_generic_hub(self) -> None:
        fragment = {
            "three_x_ui_star": {
                "id": "overlay-a",
                "hub_host": "overlay-a.example.test",
                "endpoint": {"host": "overlay-a.example.test", "port": 443, "sni": "overlay-a.example.test"},
                "panel": {"protocol": "trojan"},
                "clients": [{"host": "router1", "email": "router1"}],
            }
        }

        normalized = self.module.architecture_model_from_fragments([fragment])
        normalized = self.module.architecture_normalize(normalized)
        network = normalized["networks"]["overlay-a"]

        self.assertEqual(network["type"], "xray_overlay")
        self.assertEqual(network["hub"], "overlay-a.example.test")


if __name__ == "__main__":
    unittest.main()
