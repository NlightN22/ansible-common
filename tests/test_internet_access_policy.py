import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "plugins" / "filter" / "internet_access_policy.py"


def load_module():
    spec = importlib.util.spec_from_file_location("internet_access_policy", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class InternetAccessPolicyTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_selects_required_resources_by_layer(self):
        policy = {
            "layers": [
                {"id": "global", "resources": [{"id": "telegram", "domains": ["t.me"], "ipv4_cidrs": ["149.154.160.0/20"]}]},
                {"id": "tenant", "resources": [{"id": "mail", "fqdn": "mail.example.test", "expected_ipv4": "192.0.2.10"}]},
            ]
        }

        resources = self.module.internet_access_policy_resources(policy, ["global"])

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["resource_id"], "telegram")
        self.assertEqual(resources[0]["domains"], ["t.me"])
        self.assertEqual(resources[0]["ipv4_cidrs"], ["149.154.160.0/20"])

    def test_builds_proxy_routes_with_domains_and_expected_ipv4(self):
        policy = {
            "layers": [
                {
                    "id": "tenant",
                    "resources": [
                        {
                            "id": "mail",
                            "fqdn": "mail.example.test",
                            "expected_ipv4": "192.0.2.10",
                        }
                    ],
                }
            ]
        }

        routes = self.module.internet_access_policy_proxy_routes(policy, ["tenant"], "proxy-main")

        self.assertEqual(routes[0]["domains"], ["mail.example.test"])
        self.assertEqual(routes[0]["ipv4_cidrs"], ["192.0.2.10/32"])
        self.assertEqual(routes[0]["outbound_tag"], "proxy-main")
        self.assertTrue(self.module.internet_access_policy_routing_route_ready(routes[0]))


if __name__ == "__main__":
    unittest.main()
