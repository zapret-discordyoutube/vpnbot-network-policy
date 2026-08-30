import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicClientPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads((ROOT / "policy.json").read_text(encoding="utf-8"))
        cls.builder = load_module("vpnbot_public_policy_builder", ROOT / "tools/build_artifacts.py")

    def test_editable_policy_has_only_client_ownership(self):
        self.assertEqual("client-routing", self.policy["projection_kind"])
        self.assertEqual("end-user-device", self.policy["projection_scope"])
        self.assertEqual("vpnbot-network-policy", self.policy["canonical_owner"])
        self.assertTrue(self.policy["editable_source"])
        self.assertNotIn("node_routing", self.policy)
        serialized = json.dumps(self.policy, sort_keys=True)
        self.assertNotIn("proved_failure_action", serialized)
        self.assertNotIn("failure_action", serialized)
        self.assertNotIn('"warp"', serialized.lower())

    def test_v2rayn_order_preserves_client_direct_and_ru_blocked_proxy(self):
        files = self.builder.build_v2rayn(
            government_domains=["gov.ru"],
            government_action="direct",
            vpn_detection_domains=["api.ipify.org"],
            client_direct_server_block_domains=["api.oneme.ru"],
            russian_service_domains=["yandex.ru"],
            russian_service_action="direct",
            client_proxy_domains=["zapret.moe"],
            client_direct_domains=["loopy.ru"],
            blocked_networks=["1.1.1.1/32"],
            peer_to_peer_domains=["tracker.opentrackr.org"],
            peer_to_peer_networks=["93.158.213.92/32"],
            blocked_application_protocols=["bittorrent"],
            raw_base_url="https://policy.example/raw",
        )
        rules = json.loads(files["v2rayN/all.json"])
        positions = {rule["remarks"]: index for index, rule in enumerate(rules)}
        self.assertLess(
            positions["Проверка VPN и передача адреса заблокированы"],
            positions["Заблокированные в России домены через VPN"],
        )
        self.assertLess(
            positions["Заблокированные в России домены через VPN"],
            positions["Российские приложения, банки и маркетплейсы напрямую"],
        )
        self.assertEqual(
            "direct",
            rules[positions["Российские приложения, банки и маркетплейсы напрямую"]]["outboundTag"],
        )

    def test_checked_in_projection_is_exactly_reproducible(self):
        with tempfile.TemporaryDirectory() as raw_tmp:
            output = Path(raw_tmp) / "projection"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/build_artifacts.py"),
                    "--policy",
                    str(ROOT / "policy.json"),
                    "--output",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            summary = json.loads(result.stdout)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual("vpnbot-network-policy", summary["canonical_owner"])
            self.assertEqual("client-routing", manifest["projection_kind"])
            for relative in manifest["files"]:
                self.assertEqual(
                    (output / relative).read_bytes(),
                    (ROOT / relative).read_bytes(),
                    relative,
                )


if __name__ == "__main__":
    unittest.main()
