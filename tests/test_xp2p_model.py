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
                "in1": {
                    "id": "in1",
                    "type": "xp2p",
                    "hub": "in1.komponent-m.ru",
                    "server": "in1.komponent-m.ru",
                    "endpoint_name": "in1-komponent-m-ru",
                    "source": {
                        "id": "in1",
                        "endpoint_name": "in1-komponent-m-ru",
                        "wireguard_transport_site_ids": ["komponent", "zamena"],
                    },
                    "peers": {
                        "AB-Zavodskaya": {
                            "host": "AB-Zavodskaya",
                            "user": "ab-zavodskaya",
                        },
                        "AB-Gagarina": {
                            "host": "AB-Gagarina",
                            "user": "ab-gagarina",
                        },
                        "ad.zamena.local": {
                            "host": "ad.zamena.local",
                            "user": "ad-zamena-org",
                        },
                    },
                },
                "komponent": {
                    "id": "komponent",
                    "type": "wireguard",
                    "hub": "AB-Zavodskaya",
                    "hub_host": "AB-Zavodskaya",
                    "preferred_transport": {
                        "type": "xp2p",
                        "star": "in1",
                        "routed_cidrs": ["91.219.98.150/32"],
                    },
                },
                "zamena": {
                    "id": "zamena",
                    "type": "wireguard",
                    "hub": "ad.zamena.local",
                    "hub_host": "ad.zamena.local",
                    "preferred_transport": {
                        "type": "xp2p",
                        "star": "in1",
                        "routed_cidrs": ["185.221.214.189/32"],
                    },
                },
            },
        }

    def test_non_hub_clients_route_wireguard_endpoint_through_xp2p(self) -> None:
        view = self.module.architecture_xp2p_view(self.model, "in1", "AB-Gagarina")

        self.assertEqual(
            redirect_cidrs(view),
            {"91.219.98.150/32", "185.221.214.189/32"},
        )

    def test_wireguard_hub_does_not_route_own_public_endpoint_through_xp2p(self) -> None:
        view = self.module.architecture_xp2p_view(self.model, "in1", "AB-Zavodskaya")

        self.assertEqual(redirect_cidrs(view), {"185.221.214.189/32"})

    def test_server_reverse_redirect_points_wireguard_endpoint_to_hub_client(self) -> None:
        view = self.module.architecture_xp2p_view(self.model, "in1", "in1.komponent-m.ru")

        redirects = server_redirects_by_cidr(view)
        self.assertEqual(
            redirects["91.219.98.150/32"],
            {
                "cidr": "91.219.98.150/32",
                "host": "in1-komponent-m-ru",
                "tag": "ab-zavodskayain1-komponent-m-ru.rev",
            },
        )


if __name__ == "__main__":
    unittest.main()
