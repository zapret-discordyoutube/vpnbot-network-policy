#!/usr/bin/env python3
"""Build public client-routing projections from the canonical VPnBot policy."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT_DIR / "policy.json"
HELPER_PATH = ROOT_DIR / "tools" / "client_policy.py"
PROJECTION_KIND = "client-routing"
PROJECTION_SCOPE = "end-user-device"
CANONICAL_OWNER = "vpnbot-network-policy"
PUBLIC_REPOSITORY = "https://git.zapret.moe/zapretkvn/vpnbot-network-policy"


def load_helper():
    spec = importlib.util.spec_from_file_location("vpnbot_egress_policy_build", HELPER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load canonical policy helper: {HELPER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        tmp.write_text(payload, encoding="utf-8")
        os.chmod(tmp, 0o644)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def route_rule(*, outbound: str, remarks: str, **fields: Any) -> dict[str, Any]:
    return {
        "outboundTag": outbound,
        **fields,
        "enabled": True,
        "remarks": remarks,
    }


def domain_matchers(domains: list[str]) -> list[str]:
    return [f"domain:{domain}" for domain in domains]


def yaml_payload(values: list[str], header: str) -> str:
    ownership = (
        "CLIENT-ONLY generated projection; not a node-side firewall, "
        "server-egress policy, or editable source."
    )
    if not values:
        return f"# {ownership}\n# {header}\npayload: []\n"
    lines = [f"# {ownership}", f"# {header}", "payload:"]
    lines.extend(f"  - {json.dumps(value, ensure_ascii=False)}" for value in values)
    return "\n".join(lines) + "\n"


def build_v2rayn(
    *,
    government_domains: list[str],
    government_action: str,
    vpn_detection_domains: list[str],
    client_direct_server_block_domains: list[str],
    russian_service_domains: list[str],
    russian_service_action: str,
    client_proxy_domains: list[str],
    client_direct_domains: list[str],
    blocked_networks: list[str],
    peer_to_peer_domains: list[str],
    peer_to_peer_networks: list[str],
    blocked_application_protocols: list[str],
    raw_base_url: str,
) -> dict[str, str]:
    if russian_service_action != "direct":
        raise ValueError("Russian service client action must be direct")
    if government_action != "direct":
        raise ValueError("Government client action must be direct")
    common = [
        route_rule(
            outbound="block",
            remarks="Одноранговые загрузки заблокированы",
            protocol=blocked_application_protocols,
        ),
        route_rule(
            outbound="block",
            remarks="Блокировка рекламы",
            domain=["geosite:category-ads-all"],
        ),
        route_rule(
            outbound="direct",
            remarks="Приватные сети и домены напрямую",
            ip=["geoip:private"],
            domain=["geosite:private"],
        ),
    ]
    vpn_detection_rule = route_rule(
        outbound="block",
        remarks="Проверка VPN и передача адреса заблокированы",
        domain=domain_matchers(vpn_detection_domains),
    )
    client_direct_server_block_rule = route_rule(
        outbound="direct",
        remarks="Клиентские исключения из серверной блокировки напрямую",
        domain=domain_matchers(client_direct_server_block_domains),
    )
    # Government destinations stay hard-blocked on every VPN server, but the
    # client routes them DIRECT so the user reaches them via the home ISP.
    government_direct_rule = route_rule(
        outbound=government_action,
        remarks="Государственные сайты напрямую, VPN-сервер их отклоняет",
        domain=domain_matchers(government_domains),
    )
    blocked_network_rules: list[dict[str, Any]] = []
    if blocked_networks:
        blocked_network_rules.append(
            route_rule(
                outbound="block",
                remarks="Подтверждённые сети назначения заблокированы",
                ip=blocked_networks,
            )
        )
    russian_service_direct_rule = route_rule(
        outbound=russian_service_action,
        remarks="Российские приложения, банки и маркетплейсы напрямую",
        domain=domain_matchers(russian_service_domains),
    )
    peer_to_peer_block_rule = route_rule(
        outbound="block",
        remarks="Торрент-трекеры и DHT заблокированы",
        domain=domain_matchers(peer_to_peer_domains),
        ip=peer_to_peer_networks,
    )
    client_proxy_rule = route_rule(
        outbound="proxy",
        remarks="Проверенные исключения всегда через VPN",
        domain=domain_matchers(client_proxy_domains),
    )
    blocked_in_ru_rules = [
        route_rule(
            outbound="proxy",
            remarks="Заблокированные в России сети через VPN",
            ip=["geoip:ru-blocked"],
        ),
        route_rule(
            outbound="proxy",
            remarks="Заблокированные в России домены через VPN",
            domain=["geosite:ru-blocked"],
        ),
    ]
    exact_client_direct_rule = route_rule(
        outbound="direct",
        remarks="Проверенные российские сайты напрямую",
        domain=domain_matchers(client_direct_domains),
    )
    russian_direct_rule = route_rule(
        outbound="direct",
        remarks="Остальные российские сайты и приложения напрямую",
        ip=["geoip:ru"],
        domain=["geosite:category-ru"],
    )
    all_rules = [
        *common,
        client_direct_server_block_rule,
        government_direct_rule,
        vpn_detection_rule,
        peer_to_peer_block_rule,
        *blocked_network_rules,
        client_proxy_rule,
        *blocked_in_ru_rules,
        russian_service_direct_rule,
        exact_client_direct_rule,
        russian_direct_rule,
        route_rule(outbound="proxy", remarks="Остальное через VPN", port="0-65535"),
    ]
    # Keep this historical URL safe for clients which imported it earlier.
    # It now carries the same reviewed Russia-direct order as the primary URL.
    all_except_ru = list(all_rules)
    only_blocked_prelude = [
        *common,
        route_rule(
            outbound="proxy",
            remarks="Публичный DNS через VPN",
            ip=["1.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4"],
        ),
        route_rule(
            outbound="proxy",
            remarks="Discord voice через VPN",
            port="50000-65535",
            network="udp",
        ),
    ]
    only_blocked = [
        *only_blocked_prelude,
        client_direct_server_block_rule,
        government_direct_rule,
        vpn_detection_rule,
        peer_to_peer_block_rule,
        *blocked_network_rules,
        client_proxy_rule,
        *blocked_in_ru_rules,
        russian_service_direct_rule,
        exact_client_direct_rule,
        russian_direct_rule,
        route_rule(outbound="direct", remarks="Остальное напрямую", port="0-65535"),
    ]
    template = {
        "version": "VPnBot-Network-v3",
        "routingItems": [
            {
                "remarks": "VPnBot: Россия напрямую, остальное через VPN",
                "domainStrategy": "IPOnDemand",
                "url": f"{raw_base_url}/v2rayN/all.json",
            },
            {
                "remarks": "VPnBot: Россия напрямую (совместимый URL)",
                "domainStrategy": "IPOnDemand",
                "url": f"{raw_base_url}/v2rayN/all_except_ru.json",
            },
            {
                "remarks": "VPnBot: Только заблокированное в России",
                "domainStrategy": "IPOnDemand",
                "url": f"{raw_base_url}/v2rayN/only_blocked.json",
            },
        ],
    }
    return {
        "v2rayN/all.json": json_text(all_rules),
        "v2rayN/all_except_ru.json": json_text(all_except_ru),
        "v2rayN/only_blocked.json": json_text(only_blocked),
        "v2rayN/template.json": json_text(template),
    }


def build_route_expectations(
    *,
    policy_id: str,
    policy_version: str,
    source_policy_sha256: str,
    critical_vpn_detection_domains: list[str],
    client_direct_server_block_domains: list[str],
    extended_vpn_detection_domains: list[str],
    government_domains: list[str],
    government_action: str,
    russian_service_domains: list[str],
    russian_service_action: str,
    client_proxy_domains: list[str],
    client_direct_domains: list[str],
    peer_to_peer_domains: list[str],
) -> dict[str, Any]:
    """Build one test oracle consumed by every supported client projection."""

    cases: list[dict[str, Any]] = []
    seen_domains: set[str] = set()

    def add(
        domains: list[str],
        expected_route: str,
        policy_class: str,
        *,
        inline_required: bool = False,
        profile_modes: list[str] | None = None,
    ) -> None:
        for domain in domains:
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            cases.append(
                {
                    "domain": domain,
                    "expected_route": expected_route,
                    "policy_class": policy_class,
                    "inline_required": inline_required,
                    "profile_modes": profile_modes or ["all"],
                }
            )

    add(
        client_direct_server_block_domains,
        "direct",
        "server-block-client-direct-override",
        inline_required=True,
    )
    add(
        critical_vpn_detection_domains,
        "block",
        "vpn-detection-inline-critical",
        inline_required=True,
    )
    add(
        extended_vpn_detection_domains,
        "block",
        "vpn-detection-provider-extension",
    )
    if government_action != "direct":
        raise ValueError("Government client action must be direct")
    add(government_domains, government_action, "government-destination-client-direct")
    if russian_service_action != "direct":
        raise ValueError("Russian service client action must be direct")
    add(russian_service_domains, russian_service_action, "russian-service-client-direct")
    add(peer_to_peer_domains, "block", "peer-to-peer-discovery")
    add(client_proxy_domains, "proxy", "client-proxy-exception")
    add(client_direct_domains, "direct", "client-direct-exception")
    add(
        ["ibm.com", "stackoverflow.com", "duolingo.com"],
        "proxy",
        "vpn-default-fallback",
        profile_modes=["vpn-default"],
    )
    return {
        "schema_version": 1,
        "projection_kind": PROJECTION_KIND,
        "projection_scope": PROJECTION_SCOPE,
        "canonical_owner": CANONICAL_OWNER,
        "editable_source": False,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "source_policy_sha256": source_policy_sha256,
        "cases": cases,
    }


def build_mihomo_runtime_snapshot(
    *,
    policy_id: str,
    policy_version: str,
    source_policy_sha256: str,
    critical_vpn_detection_domains: list[str],
    client_direct_server_block_domains: list[str],
    extended_vpn_detection_domains: list[str],
    government_domains: list[str],
    government_action: str,
    russian_service_domains: list[str],
    russian_service_action: str,
    client_proxy_domains: list[str],
    client_direct_domains: list[str],
    blocked_networks: list[str],
    peer_to_peer_domains: list[str],
    peer_to_peer_networks: list[str],
    ru_blocked_domain_provider_url: str,
    ru_blocked_network_provider_url: str,
) -> dict[str, Any]:
    if russian_service_action != "direct":
        raise ValueError("Russian service client action must be direct")
    if government_action != "direct":
        raise ValueError("Government client action must be direct")
    providers = {
        "vpn_detection_extensions": {
            "behavior": "domain",
            "payload": [f"+.{domain}" for domain in extended_vpn_detection_domains],
        },
        "government_domains": {
            "behavior": "domain",
            "payload": [f"+.{domain}" for domain in government_domains],
        },
        "government_networks": {
            "behavior": "ipcidr",
            "payload": list(blocked_networks),
        },
        "russian_service_domains": {
            "behavior": "domain",
            "payload": [f"+.{domain}" for domain in russian_service_domains],
        },
        "client_proxy_domains": {
            "behavior": "domain",
            "payload": [f"+.{domain}" for domain in client_proxy_domains],
        },
        "client_direct_domains": {
            "behavior": "domain",
            "payload": [f"+.{domain}" for domain in client_direct_domains],
        },
        "peer_to_peer_domains": {
            "behavior": "domain",
            "payload": [f"+.{domain}" for domain in peer_to_peer_domains],
        },
        "peer_to_peer_networks": {
            "behavior": "ipcidr",
            "payload": list(peer_to_peer_networks),
        },
    }
    provider_sha256 = hashlib.sha256(
        json.dumps(
            providers,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    external_rule_providers = {
        "ru_blocked_domains": {
            "behavior": "domain",
            "format": "text",
            "url": ru_blocked_domain_provider_url,
            "path": "./ruleset/vpnbot-ru-blocked-domains.txt",
            "interval": 21600,
        },
        "ru_blocked_networks": {
            "behavior": "ipcidr",
            "format": "mrs",
            "url": ru_blocked_network_provider_url,
            "path": "./ruleset/vpnbot-ru-blocked-networks.mrs",
            "interval": 21600,
        },
    }
    external_provider_sha256 = hashlib.sha256(
        json.dumps(
            external_rule_providers,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 1,
        "projection_kind": PROJECTION_KIND,
        "projection_scope": PROJECTION_SCOPE,
        "canonical_owner": CANONICAL_OWNER,
        "editable_source": False,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "russian_service_domain_action": russian_service_action,
        "government_domain_action": government_action,
        "source_policy_sha256": source_policy_sha256,
        "provider_snapshot_sha256": provider_sha256,
        "external_provider_snapshot_sha256": external_provider_sha256,
        "critical_vpn_detection_domain_suffixes": critical_vpn_detection_domains,
        "client_direct_server_block_domain_suffixes": (
            client_direct_server_block_domains
        ),
        "providers": providers,
        "external_rule_providers": external_rule_providers,
    }


def build_readme(policy: dict[str, Any], source_sha256: str) -> str:
    client = policy["client_routing"]
    template_url = f"{client['raw_base_url']}/v2rayN/template.json"
    return f"""# VPnBot network policy

Публичная клиентская маршрутизация VPnBot. Редактируемый источник находится в
`policy.json`, а этот скрипт атомарно строит из него Mihomo, v2rayN и остальные
проверяемые клиентские проекции.

## Важно: это только клиентская маршрутизация

Этот репозиторий загружают **клиентские приложения на устройствах
пользователей**: Mihomo/Clash Meta и v2rayN. Он определяет, какой трафик
устройство отправляет `DIRECT`, `REJECT` или в выбранный VPN-профиль.

Он **не** является node-side firewall, не устанавливается на VPN-ноду как
источник server egress и не решает, должен ли уже принятый нодой трафик выйти
напрямую, через WARP либо быть заблокированным. Node-side действия принадлежат
приватному компоненту `vpnbot_node_services/services/network-policy`. Эти две
политики имеют независимых владельцев и не генерируют друг друга.

`policy.json` — единственный редактируемый источник клиентской маршрутизации.
Сгенерированные каталоги и manifest вручную не редактируются: их пересобирает
`tools/build_artifacts.py` в этом же репозитории.

Версия политики: `{client['policy_version']}`.

Исходная политика SHA-256: `{source_sha256}`.

## v2rayN для Windows

1. Откройте в главном меню v2rayN «Настройка региональных пресетов» → «Россия».
   Этот шаг задаёт российские источники `geoip.dat` и `geosite.dat` из
   [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat).
2. Обновите Geo-файлы через меню проверки обновлений. Они нужны и для
   `ru-blocked → proxy`, и для `category-ru/geoip:ru → direct`.
3. В окне обычных настроек замените поле «Источник правил маршрутизации
   (необязательно)» на:

   `{template_url}`

4. Откройте «Настройка правил», выберите
   `VPnBot: Россия напрямую, остальное через VPN`, выполните «Импорт правил из URL» и
   установите этот набор активным. Названия пунктов могут немного отличаться
   между версиями v2rayN, но исходный URL остаётся тем же.

После первого импорта повторяйте обновление правил из URL, когда v2rayN не
обновляет внешний шаблон автоматически. Сам публичный набор VPnBot и его
Mihomo-проекции обновляются без изменения адресов.

Правила проверяются сверху вниз. Сначала применяются явные клиентские исключения
из серверной блокировки: `api.oneme.ru` и государственные сайты (`mos.ru`,
`gosuslugi.ru` и другие) идут напрямую через домашнего провайдера, хотя каждый
VPN-сервер продолжает отклонять эти назначения. Затем локально
блокируются подтверждённые каналы VPN-детектирования и P2P.
Затем ресурсы из `ru-blocked` идут через VPN. После них российские приложения,
банки, маркетплейсы и проверенные клиентские исключения (`api.oneme.ru`,
`loopy.ru` и `championat.com`) идут напрямую вместе с остальными
`category-ru`/`geoip:ru`.
Так обычные VK, Mail.ru, MAX, банки и магазины не ломаются в клиентской
подписке, а заблокированные в России сайты продолжают открываться через VPN.
Остальные узкие подтверждённые служебные адреса проверки VPN остаются выше
общих российских правил и по-прежнему отклоняются.

## Mihomo / Clash Meta

Профиль, выданный ботом, содержит одно раннее клиентское исключение DIRECT и
11 критических VPN-detection суффиксов REJECT прямо в YAML, а также проверенный
снимок собственных provider-файлов. Большие динамические
списки `ru-blocked` подключаются отдельными штатными rule-provider: домены в
текстовом формате, сети в двоичном формате Mihomo MRS. Поэтому клиенту не нужно
успеть заменить встроенную `geosite.dat` до первой проверки YAML; оба внешних
списка обновляются самим Mihomo каждые шесть часов. Версия политики и её
SHA-256 видны в комментариях в начале профиля. Ручная настройка не нужна.

## Внешние данные

- Mihomo получает `ru-blocked` как отдельные domain/IP rule-provider из
  [runetfreedom/russia-blocked-geosite](https://github.com/runetfreedom/russia-blocked-geosite)
  и [runetfreedom/russia-blocked-geoip](https://github.com/runetfreedom/russia-blocked-geoip).
  v2rayN продолжает получать `geoip:ru-blocked`, `geosite:ru-blocked`,
  `geoip:ru` и `geosite:category-ru` из
  [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat).
- Коммерческие ASN Яндекса, VK и Ozon намеренно не блокируются: ASN слишком
  широк для безопасной государственной границы и может содержать обычных
  пользователей или общую инфраструктуру.
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path)
    args = parser.parse_args()

    helper = load_helper()
    policy = helper.load_config(args.policy)
    # --cache-dir is intentionally retained as a compatibility-only CLI flag.
    # Schema 2 no longer downloads or caches broad RU/ASN source material.
    source_bytes = args.policy.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    government_domains = helper.blocked_government_domains(policy)
    vpn_detection_domains = helper.client_blocked_vpn_detection_domains(policy)
    client_direct_server_block_domains = (
        helper.client_direct_server_block_domains(policy)
    )
    critical_vpn_detection_domains = helper.critical_vpn_detection_domains(policy)
    extended_vpn_detection_domains = helper.extended_vpn_detection_domains(policy)
    russian_service_domains = helper.blocked_russian_service_domains(policy)
    client_proxy_domains = helper.client_proxy_domains(policy)
    client_direct_domains = helper.client_direct_domains(policy)
    blocked_networks = list(policy["blocked_destination_cidrs"])
    peer_to_peer_domains = helper.blocked_peer_to_peer_domains(policy)
    peer_to_peer_networks = helper.blocked_peer_to_peer_networks(policy)
    blocked_application_protocols = helper.blocked_application_protocols(policy)
    government_action = str(policy["client_routing"]["government_domain_action"])
    files = build_v2rayn(
        government_domains=government_domains,
        government_action=government_action,
        vpn_detection_domains=vpn_detection_domains,
        client_direct_server_block_domains=client_direct_server_block_domains,
        russian_service_domains=russian_service_domains,
        russian_service_action=str(
            policy["client_routing"]["russian_service_domain_action"]
        ),
        client_proxy_domains=client_proxy_domains,
        client_direct_domains=client_direct_domains,
        blocked_networks=blocked_networks,
        peer_to_peer_domains=peer_to_peer_domains,
        peer_to_peer_networks=peer_to_peer_networks,
        blocked_application_protocols=blocked_application_protocols,
        raw_base_url=str(policy["client_routing"]["raw_base_url"]).rstrip("/"),
    )
    files.update(
        {
            "mihomo/proxy-exceptions.yaml": yaml_payload(
                [],
                "Legacy compatibility provider. Ordinary destinations use the selected VPN.",
            ),
            "mihomo/direct-domains.yaml": yaml_payload(
                [],
                "Legacy compatibility provider. Broad RU DIRECT routing is retired.",
            ),
            "mihomo/direct-ipcidr.yaml": yaml_payload(
                [],
                "Legacy compatibility provider. Broad RU network routing is retired.",
            ),
            "mihomo/blocked-government-domains.yaml": yaml_payload(
                [
                    f"+.{domain}"
                    for domain in [
                        *vpn_detection_domains,
                        *peer_to_peer_domains,
                    ]
                ],
                "Compatibility deny provider for existing Mihomo profiles. "
                "Government destinations now use DIRECT in clients.",
            ),
            "mihomo/blocked-government-only-domains.yaml": yaml_payload(
                [],
                "Retired compatibility deny provider. "
                "Government destinations now use DIRECT in clients.",
            ),
            "mihomo/client-direct-government-domains.yaml": yaml_payload(
                [f"+.{domain}" for domain in government_domains],
                "Generated government destinations that use DIRECT in clients "
                "while every VPN server still rejects them.",
            ),
            "mihomo/blocked-vpn-detection-domains.yaml": yaml_payload(
                [f"+.{domain}" for domain in vpn_detection_domains],
                "Generated VPN-detection and VPN-address exfiltration destinations.",
            ),
            "mihomo/blocked-vpn-detection-extensions.yaml": yaml_payload(
                [f"+.{domain}" for domain in extended_vpn_detection_domains],
                "Generated non-critical VPN-detection provider extensions.",
            ),
            "mihomo/blocked-russian-service-domains.yaml": yaml_payload(
                [],
                "Retired compatibility deny provider. Russian services now use DIRECT.",
            ),
            "mihomo/client-direct-russian-service-domains.yaml": yaml_payload(
                [f"+.{domain}" for domain in russian_service_domains],
                "Generated Russian apps, banks and marketplaces that use DIRECT in clients.",
            ),
            "mihomo/blocked-peer-to-peer-domains.yaml": yaml_payload(
                [f"+.{domain}" for domain in peer_to_peer_domains],
                "Generated peer-to-peer tracker and DHT destination suffixes.",
            ),
            "mihomo/blocked-peer-to-peer-ipcidr.yaml": yaml_payload(
                peer_to_peer_networks,
                "Generated exact peer-to-peer discovery destination CIDRs.",
            ),
            "mihomo/client-direct-domains.yaml": yaml_payload(
                [f"+.{domain}" for domain in client_direct_domains],
                "Generated exact client domain suffixes that must use DIRECT.",
            ),
            "mihomo/client-proxy-domains.yaml": yaml_payload(
                [f"+.{domain}" for domain in client_proxy_domains],
                "Generated exact client domain suffixes that must use the VPN.",
            ),
            "mihomo/blocked-government-ipcidr.yaml": yaml_payload(
                blocked_networks,
                "Generated exact government destination CIDRs that must be rejected.",
            ),
            "generated/destination-asn-prefixes.json": json_text(
                {
                    "schema_version": 3,
                    "source_policy_sha256": source_sha256,
                    "asns": [],
                    "asn_prefixes": [],
                    "networks": {"4": [], "6": []},
                    "retired_reason": "ASN-wide destination blocking is unsafe",
                }
            ),
            "generated/route-expectations.json": json_text(
                build_route_expectations(
                    policy_id=policy["policy_id"],
                    policy_version=policy["client_routing"]["policy_version"],
                    source_policy_sha256=source_sha256,
                    critical_vpn_detection_domains=critical_vpn_detection_domains,
                    client_direct_server_block_domains=(
                        client_direct_server_block_domains
                    ),
                    extended_vpn_detection_domains=extended_vpn_detection_domains,
                    government_domains=government_domains,
                    government_action=government_action,
                    russian_service_domains=russian_service_domains,
                    russian_service_action=str(
                        policy["client_routing"]["russian_service_domain_action"]
                    ),
                    client_proxy_domains=client_proxy_domains,
                    client_direct_domains=client_direct_domains,
                    peer_to_peer_domains=peer_to_peer_domains,
                )
            ),
            "generated/mihomo-runtime-policy.json": json_text(
                build_mihomo_runtime_snapshot(
                    policy_id=policy["policy_id"],
                    policy_version=policy["client_routing"]["policy_version"],
                    source_policy_sha256=source_sha256,
                    critical_vpn_detection_domains=critical_vpn_detection_domains,
                    client_direct_server_block_domains=(
                        client_direct_server_block_domains
                    ),
                    extended_vpn_detection_domains=extended_vpn_detection_domains,
                    government_domains=government_domains,
                    government_action=government_action,
                    russian_service_domains=russian_service_domains,
                    russian_service_action=str(
                        policy["client_routing"]["russian_service_domain_action"]
                    ),
                    client_proxy_domains=client_proxy_domains,
                    client_direct_domains=client_direct_domains,
                    blocked_networks=blocked_networks,
                    peer_to_peer_domains=peer_to_peer_domains,
                    peer_to_peer_networks=peer_to_peer_networks,
                    ru_blocked_domain_provider_url=str(
                        policy["client_routing"][
                            "runetfreedom_ru_blocked_domain_provider_url"
                        ]
                    ),
                    ru_blocked_network_provider_url=str(
                        policy["client_routing"][
                            "runetfreedom_ru_blocked_network_provider_url"
                        ]
                    ),
                )
            ),
            # policy.json is the editable source, not another generated
            # projection.  Preserve its exact bytes so a build into the
            # repository cannot silently normalize or mutate its own input.
            "policy.json": source_bytes.decode("utf-8"),
            "README.md": build_readme(policy, source_sha256),
        }
    )
    for relative, payload in files.items():
        atomic_write(args.output / relative, payload)

    manifest_files: dict[str, dict[str, Any]] = {}
    for relative in sorted(files):
        path = args.output / relative
        manifest_files[relative] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
    manifest = {
        "schema_version": 1,
        "projection_kind": PROJECTION_KIND,
        "projection_scope": PROJECTION_SCOPE,
        "canonical_owner": CANONICAL_OWNER,
        "editable_source": True,
        "public_repository": PUBLIC_REPOSITORY,
        "policy_id": policy["policy_id"],
        "source_policy_sha256": source_sha256,
        "files": manifest_files,
    }
    atomic_write(args.output / "manifest.json", json_text(manifest))
    print(
        json.dumps(
            {
                "output": str(args.output),
                "projection_kind": PROJECTION_KIND,
                "projection_scope": PROJECTION_SCOPE,
                "canonical_owner": CANONICAL_OWNER,
                "source_policy_sha256": source_sha256,
                "files": len(files) + 1,
                "client_direct_domains": len(client_direct_domains),
                "client_proxy_domains": len(client_proxy_domains),
                "critical_vpn_detection_domains": len(critical_vpn_detection_domains),
                "client_direct_server_block_domains": len(
                    client_direct_server_block_domains
                ),
                "extended_vpn_detection_domains": len(extended_vpn_detection_domains),
                "government_domains": len(government_domains),
                "vpn_detection_domains": len(vpn_detection_domains),
                "russian_service_domains": len(russian_service_domains),
                "blocked_networks": len(blocked_networks),
                "peer_to_peer_domains": len(peer_to_peer_domains),
                "peer_to_peer_networks": len(peer_to_peer_networks),
                "blocked_application_protocols": len(blocked_application_protocols),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
