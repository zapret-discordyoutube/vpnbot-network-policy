#!/usr/bin/env python3
"""Client-only policy loader used by the public projection builder."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Iterable


def normalized_domains(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    for raw in values:
        domain = str(raw or "").strip().lower().rstrip(".")
        if domain.startswith("domain:"):
            domain = domain[7:]
        if not domain or any(char.isspace() for char in domain):
            raise ValueError("client policy contains an invalid domain")
        domain = domain.encode("idna").decode("ascii")
        if domain in result:
            raise ValueError("client policy contains a duplicate domain")
        result.append(domain)
    return result


def load_config(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 3
        or payload.get("policy_id") != "vpnbot-network-policy-v3"
    ):
        raise ValueError("client policy schema is unsupported")
    client = payload.get("client_routing")
    if not isinstance(client, dict):
        raise ValueError("client_routing is missing")
    if client.get("russian_service_domain_action") != "direct":
        raise ValueError("Russian-service client action must remain direct")
    if client.get("government_domain_action") != "direct":
        raise ValueError("government client action must remain direct")
    for field in (
        "raw_base_url",
        "runetfreedom_ru_blocked_domain_provider_url",
        "runetfreedom_ru_blocked_network_provider_url",
    ):
        if not str(client.get(field) or "").startswith("https://"):
            raise ValueError(f"{field} must use HTTPS")
    detection = payload.get("blocked_vpn_detection_domain_suffixes")
    if not isinstance(detection, list) or len(detection) != 12:
        raise ValueError("client VPN-detection catalogue must contain 12 rows")
    for row in detection:
        if (
            not isinstance(row, dict)
            or row.get("client_rule_tier")
            not in {"inline-critical", "provider-extension"}
            or row.get("client_action") not in {"block", "direct"}
        ):
            raise ValueError("client VPN-detection row is invalid")
    payload["blocked_destination_cidrs"] = _networks(
        payload.get("blocked_destination_cidrs") or []
    )
    peer = payload.get("peer_to_peer_protection")
    if not isinstance(peer, dict):
        raise ValueError("peer-to-peer client policy is missing")
    peer["blocked_destination_cidrs"] = _networks(
        peer.get("blocked_destination_cidrs") or []
    )
    return payload


def _networks(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        network = str(ipaddress.ip_network(str(value), strict=True))
        if network in result:
            raise ValueError("client policy contains a duplicate network")
        result.append(network)
    return result


def blocked_application_protocols(config: dict[str, Any]) -> list[str]:
    return list(config["peer_to_peer_protection"]["blocked_application_protocols"])


def blocked_government_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(
        [
            *config["blocked_government_domain_suffixes"],
            *config["blocked_government_domain_hosts"],
        ]
    )


def blocked_peer_to_peer_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(config["peer_to_peer_protection"]["blocked_domain_suffixes"])


def blocked_peer_to_peer_networks(config: dict[str, Any]) -> list[str]:
    return list(config["peer_to_peer_protection"]["blocked_destination_cidrs"])


def blocked_russian_service_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(
        row["domain_suffix"]
        for row in config["blocked_russian_service_domain_suffixes"]
    )


def client_blocked_vpn_detection_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(
        row["domain_suffix"]
        for row in config["blocked_vpn_detection_domain_suffixes"]
        if row["client_action"] == "block"
    )


def client_direct_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(
        [
            *config["client_routing"]["direct_domain_suffixes"],
            *client_direct_server_block_domains(config),
        ]
    )


def client_direct_server_block_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(
        row["domain_suffix"]
        for row in config["blocked_vpn_detection_domain_suffixes"]
        if row["client_action"] == "direct"
    )


def client_proxy_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(config["client_routing"]["proxy_domain_suffixes"])


def critical_vpn_detection_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(
        row["domain_suffix"]
        for row in config["blocked_vpn_detection_domain_suffixes"]
        if row["client_rule_tier"] == "inline-critical"
        and row["client_action"] == "block"
    )


def extended_vpn_detection_domains(config: dict[str, Any]) -> list[str]:
    return normalized_domains(
        row["domain_suffix"]
        for row in config["blocked_vpn_detection_domain_suffixes"]
        if row["client_rule_tier"] == "provider-extension"
        and row["client_action"] == "block"
    )
