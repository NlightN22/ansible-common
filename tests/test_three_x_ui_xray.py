from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "plugins" / "module_utils" / "three_x_ui_xray.py"


def load_module():
    spec = importlib.util.spec_from_file_location("three_x_ui_xray", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reconcile_adopts_single_loopback_socks_inbound() -> None:
    module = load_module()
    config = {
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth"},
                "tag": "manual-socks",
            }
        ],
        "routing": {"rules": [module.API_ROUTE]},
    }

    result = module.reconcile_xray_config(
        config,
        {
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": 1080,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "tag": "managed-local-socks",
                    "adopt_existing": True,
                }
            ]
        },
    )

    assert result["inbounds_updated"] == 1
    assert config["inbounds"] == [
        {
            "listen": "127.0.0.1",
            "port": 1080,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "tag": "managed-local-socks",
        }
    ]


def test_reconcile_is_idempotent_for_existing_inbound_and_route() -> None:
    module = load_module()
    route = {
        "type": "field",
        "outboundTag": "ab-zavodskaya.rev",
        "ip": ["172.16.16.0/23"],
    }
    inbound = {
        "listen": "127.0.0.1",
        "port": 1080,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "tag": "managed-local-socks",
    }
    config = {
        "inbounds": [inbound.copy()],
        "reverse": {"portals": [{"tag": "ab-zavodskaya.rev", "domain": "ab-zavodskaya.rev"}]},
        "routing": {"rules": [module.API_ROUTE, route.copy()]},
    }

    result = module.reconcile_xray_config(
        config,
        {
            "inbounds": [inbound],
            "reverse_portals": [{"tag": "ab-zavodskaya.rev", "domain": "ab-zavodskaya.rev"}],
            "routes": [route],
        },
    )

    assert not any(result.values())
