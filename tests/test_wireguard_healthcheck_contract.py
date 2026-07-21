from __future__ import annotations

from pathlib import Path


ROLES_PATH = Path(__file__).resolve().parents[1] / "roles"


def role_tasks(role: str) -> str:
    return (ROLES_PATH / role / "tasks" / "main.yml").read_text()


def test_mikrotik_endpoint_route_checks_dns_and_active_route_selection() -> None:
    tasks = role_tasks("wireguard_mikrotik_healthcheck")

    assert "Check MikroTik endpoint active route for DNS endpoint" in tasks
    assert ':resolve "{{ resolved_wireguard_network.endpoint.host }}"' in tasks
    assert "routing route print detail where active and dst-address in $endpointAddress" in tasks
    assert "ip route print detail where active and dst-address in $endpointAddress" in tasks
    assert "mikrotik_wireguard_endpoint_expected_interface" in tasks
    assert "immediate-gw" in tasks


def test_mikrotik_reachability_requires_zero_packet_loss() -> None:
    tasks = role_tasks("wireguard_mikrotik_healthcheck")

    assert "received=' ~ (mikrotik_wireguard_verify_ping_count | int | string)" in tasks
    assert "packet-loss=0%" in tasks
    assert "packet-loss=100%" not in tasks


def test_linux_endpoint_route_checks_selected_transport_interface() -> None:
    tasks = role_tasks("wireguard_linux_healthcheck")

    assert "wireguard_linux_endpoint_expected_interface" in tasks
    assert "ENDPOINT_ROUTE_LOOP" in tasks
    assert "ENDPOINT_ROUTE_TRANSPORT_MISMATCH" in tasks
    assert "ip route get \"$endpoint_host\"" in tasks


def test_windows_endpoint_route_checks_selected_transport_interface() -> None:
    tasks = role_tasks("wireguard_windows_healthcheck")

    assert "wireguard_windows_endpoint_expected_interface" in tasks
    assert "Find-NetRoute -RemoteIPAddress $address" in tasks
    assert "WireGuard endpoint route to $endpointHost loops through $tunnelName." in tasks
    assert "expected $endpointExpectedInterface" in tasks
    assert "ping.exe -S $pingSourceAddress" in tasks
