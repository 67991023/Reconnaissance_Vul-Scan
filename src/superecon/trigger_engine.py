from dataclasses import dataclass, field
from pathlib import Path
import yaml

from superecon.dataModel import Port


@dataclass
class TriggerMatch:
    port: Port
    plugin_names: list[str]


@dataclass
class SkippedAction:
    """เก็บว่า trigger ไหนถูกข้าม เพราะอะไร"""
    port_number: int
    plugin_name: str
    reason: str


class TriggerEngine:
    def __init__(self, config_path: Path, enabled_flags: set[str] | None = None):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        self.rules: list[dict] = config.get("triggers", [])
        self.enabled_flags: set[str] = enabled_flags or set()
        self.skipped: list[SkippedAction] = []
        # ↑ กล่องเก็บ "ป้ายบอกทาง" ทั้งหมด — เริ่มต้นเป็นกล่องเปล่า
        #   จะถูกเติมของระหว่างที่ resolve() ทำงาน

    def _rule_matches_port(self, rule_match: dict, port: Port) -> bool:
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
        self.skipped = []   # ล้างของเก่าทุกครั้งที่เรียก resolve() ใหม่ (กันข้อมูลค้าง)
        matches = []

        for port in ports:
            if port.state != "open":
                continue

            matched_plugins: list[str] = []
            for rule in self.rules:
                if self._rule_matches_port(rule["match"], port):

                    needed_flag = rule.get("requires_flag")
                    if needed_flag and needed_flag not in self.enabled_flags:
                        # แทนที่จะ continue เงียบๆ — จดป้ายบอกทางไว้ก่อน
                        for plugin_name in rule["plugins"]:
                            self.skipped.append(SkippedAction(
                                port_number=port.number,
                                plugin_name=plugin_name,
                                reason=f"requires --{needed_flag.replace('_', '-')}",
                            ))
                        continue

                    matched_plugins.extend(rule["plugins"])

            if matched_plugins:
                unique_plugins = list(dict.fromkeys(matched_plugins))
                matches.append(TriggerMatch(port=port, plugin_names=unique_plugins))

        return matches

    def get_skipped(self) -> list[SkippedAction]:
        """เรียกดู list ของป้ายบอกทางทั้งหมดหลัง resolve() ทำงานเสร็จ"""
        return self.skipped