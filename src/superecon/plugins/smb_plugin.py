import subprocess
from pathlib import Path

from superecon.dataModel import Port, Finding, PluginResult
from superecon.plugins.base import ScanPlugin
from superecon.plugins.registry import register_plugin


@register_plugin
class SMBPlugin(ScanPlugin):
    name = "smb_plugin"
    required_binaries = ["smbclient"]

    def run(self, target_host: str, port: Port, output_dir: Path) -> PluginResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        outfile = output_dir / "smb_shares.txt"
        findings: list[Finding] = []

        cmd = ["smbclient", "-L", f"//{target_host}/", "-N"]
        # -N คือ "ไม่ต้องใส่ password" (anonymous/null session)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            outfile.write_text(result.stdout)

            if "NT_STATUS_ACCESS_DENIED" not in result.stdout and "Sharename" in result.stdout:
                findings.append(Finding(
                    severity="critical",
                    title="SMB anonymous listing สำเร็จ",
                    detail="เข้าถึง share list ได้โดยไม่ต้อง login — ดู smb_shares.txt",
                ))
        except subprocess.TimeoutExpired:
            findings.append(Finding(severity="info", title="smb check timeout"))

        return PluginResult(plugin_name=self.name, port=port.number, success=True,
                             findings=findings, output_files=[outfile])