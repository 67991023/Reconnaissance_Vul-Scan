import subprocess
from pathlib import Path

from superecon.dataModel import Port, Finding, PluginResult
from superecon.plugins.base import ScanPlugin
from superecon.plugins.registry import register_plugin


@register_plugin
class FTPPlugin(ScanPlugin):
    name = "ftp_plugin"
    required_binaries = ["nmap"]

    def run(self, target_host: str, port: Port, output_dir: Path) -> PluginResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        outfile = output_dir / "ftp_anon_check.txt"
        findings: list[Finding] = []

        cmd = ["nmap", "-p", str(port.number), "--script", "ftp-anon,ftp-syst",
               target_host, "-oN", str(outfile)]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            outfile.write_text(result.stdout)

            if "Anonymous FTP login allowed" in result.stdout:
                findings.append(Finding(
                    severity="critical",
                    title="Anonymous FTP login allowed",
                    detail="ดู ftp_anon_check.txt สำหรับรายละเอียดไฟล์ที่ list ได้",
                ))
        except subprocess.TimeoutExpired:
            findings.append(Finding(severity="info", title="ftp check timeout"))

        return PluginResult(plugin_name=self.name, port=port.number, success=True,
                             findings=findings, output_files=[outfile])