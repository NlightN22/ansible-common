from pathlib import Path


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
