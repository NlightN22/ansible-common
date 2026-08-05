from pathlib import Path
import json
import shutil
import subprocess


ROOT = Path(__file__).parents[1]
FAILOVER_TEMPLATE = (
    ROOT / "roles/openwrt_transport_failover/templates/openwrt-transport-failover.sh.j2"
).read_text(encoding="utf-8")
ROUTE_CONTROL_TEMPLATE = (
    ROOT / "roles/openwrt_route_control/templates/openwrt-route-control-runtime.sh.j2"
).read_text(encoding="utf-8")
HEALTH_TASKS = (
    ROOT / "roles/transport_health/tasks/candidate.yml"
).read_text(encoding="utf-8")


def test_failover_delegates_runtime_dataplane_changes_to_route_control():
    assert "route_control_helper='" in FAILOVER_TEMPLATE
    assert 'replace-xray-outbound "$routing_file"' in FAILOVER_TEMPLATE
    assert 'set-intercept disabled' in FAILOVER_TEMPLATE
    assert 'set-intercept enabled' in FAILOVER_TEMPLATE
    assert 'set-route-interface "$selected_interface"' in FAILOVER_TEMPLATE
    assert 'uci commit network' not in FAILOVER_TEMPLATE
    assert '/etc/init.d/network reload' not in FAILOVER_TEMPLATE


def test_route_control_runtime_helper_owns_runtime_mutations():
    assert "uci commit network" in ROUTE_CONTROL_TEMPLATE
    assert "replace-xray-outbound)" in ROUTE_CONTROL_TEMPLATE
    assert ".rules |= map(" in ROUTE_CONTROL_TEMPLATE


def test_transport_health_requires_specific_wireguard_peer():
    assert "endpoint.peer_public_key" in HEALTH_TASKS
    assert 'latest-handshakes "$peer_public_key"' in HEALTH_TASKS


def test_terminal_direct_is_wan_fallback_not_active_xray_outbound(tmp_path):
    jq = shutil.which("jq")
    if jq is None:
        raise AssertionError("jq is required for the routing resolver regression test")

    routing_file = tmp_path / "routing.json"
    routing_file.write_text(
        json.dumps(
            {
                "rules": [
                    {"domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                    {"ip": ["1.1.1.1/32"], "outboundTag": "proxy-dcpkt2-ddns-net"},
                    {"network": "tcp,udp", "outboundTag": "direct"},
                ]
            }
        ),
        encoding="utf-8",
    )
    resolver = (
        "[.rules[]?.outboundTag? as $tag | "
        "select($tag != null and ($candidates | index($tag)) != null) | $tag] "
        "| if length > 0 then .[0] else \"\" end"
    )
    result = subprocess.run(
        [
            jq,
            "-r",
            "--argjson",
            "candidates",
            '["proxy-dcpkt2-ddns-net", "proxy-ex4-ddns-net"]',
            resolver,
            str(routing_file),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "proxy-dcpkt2-ddns-net"
    assert ".rules[-1].outboundTag as $tag |\n    if ($tag != null and ($candidates" not in FAILOVER_TEMPLATE
    assert "routing_wan_fallback" in FAILOVER_TEMPLATE
    assert "active_xray_outbound" in FAILOVER_TEMPLATE
