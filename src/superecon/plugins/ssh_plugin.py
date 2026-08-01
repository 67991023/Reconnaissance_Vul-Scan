import subprocess
from pathlib import Path

from superecon.dataModel import Port, Finding, PluginResult
from superecon.plugins.base import ScanPlugin
from superecon.plugins.registry import register_plugin


@register_plugin
class SSHPlugin(ScanPlugin):
    name = "ssh_plugin"
    required_binaries = ["nmap"]

    def run(self, target_host: str, port: Port, output_dir: Path) -> PluginResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        outfile = output_dir / "ssh_enum.txt"
        findings: list[Finding] = []

        cmd = ["nmap", "-p", str(port.number), "--script", "ssh2-enum-algos,ssh-auth-methods",
               target_host, "-oN", str(outfile)]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            outfile.write_text(result.stdout)
            findings.append(Finding(severity="info", title="SSH algorithm/auth enum เสร็จแล้ว",
                                     detail="ดู ssh_enum.txt เทียบ version กับ known CVE ด้วยมือ"))
        except subprocess.TimeoutExpired:
            findings.append(Finding(severity="info", title="ssh check timeout"))

        return PluginResult(plugin_name=self.name, port=port.number, success=True,
                             findings=findings, output_files=[outfile])