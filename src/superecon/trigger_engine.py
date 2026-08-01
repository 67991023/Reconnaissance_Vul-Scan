from dataclasses import dataclass
from pathlib import Path
import yaml

from superecon.dataModel import Port


@dataclass
class TriggerMatch:
    """ผลลัพธ์ 1 รายการ: 'port นี้ ควรเรียก plugin เหล่านี้'"""
    port: Port
    plugin_names: list[str]


class TriggerEngine:
    def __init__(self, config_path: Path, enabled_flags: set[str] | None = None):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        self.rules: list[dict] = config.get("triggers", [])
        self.enabled_flags: set[str] = enabled_flags or set()

    def _rule_matches_port(self, rule_match: dict, port: Port) -> bool:
        """เช็คว่า 1 port ตรงกับเงื่อนไข match ของ 1 rule หรือไม่"""

        expected_port = rule_match.get("port")
        if expected_port is not None and expected_port != port.number:
            return False

        expected_keywords = rule_match.get("service_contains")
        if expected_keywords is not None:
            if port.service is None:
                return False

            service_name = port.service.name.lower()
            if not any(kw.lower() in service_name for kw in expected_keywords):
                return False

        return True

    def resolve(self, ports: list[Port]) -> list[TriggerMatch]:
        """รับ list ของ port ทั้งหมด คืน list ของ TriggerMatch"""
        matches = []

        for port in ports:
            if port.state != "open":
                continue

            matched_plugins: list[str] = []
            for rule in self.rules:
                if self._rule_matches_port(rule["match"], port):

                    needed_flag = rule.get("requires_flag")
                    if needed_flag and needed_flag not in self.enabled_flags:
                        continue

                    matched_plugins.extend(rule["plugins"])

            if matched_plugins:
                unique_plugins = list(dict.fromkeys(matched_plugins))
                matches.append(TriggerMatch(port=port, plugin_names=unique_plugins))

        return matches