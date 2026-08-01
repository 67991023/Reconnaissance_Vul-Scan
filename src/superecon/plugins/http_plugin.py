import json
import subprocess
from pathlib import Path

from superecon.dataModel import Port, Finding, PluginResult
from superecon.plugins.base import ScanPlugin
from superecon.plugins.registry import register_plugin

@register_plugin
class HTTPPlugin(ScanPlugin):
    name = "http_plugin"

    required_binaries = ["httpx", "ffuf"]

    def run(self, target_host: str, port: Port, output_dir: Path) -> PluginResult:
        output_dir.mkdir(parents=True, exist_ok=True)

        scheme = "https" if port.number in (443, 8443) else "http"
        base_url = f"{scheme}://{target_host}:{port.number}/"

        findings: list[Finding] = []
        output_files: list[Path] = []

        httpx_outfile = output_dir / "httpx.json"
        httpx_cmd = ["httpx", "-u", base_url, "-title", "-status-code", "-tech-detect", "-json"]

        try:
            result = subprocess.run(httpx_cmd, capture_output=True, text=True, timeout=30)
            httpx_outfile.write_text(result.stdout)
            output_files.append(httpx_outfile)

            if result.stdout.strip():
                data = json.loads(result.stdout.strip().splitlines()[0])

                title = data.get("title", "")
                tech = data.get("tech", [])
                findings.append(Finding(
                    severity="info",
                    title=f"Web service alive: {title or 'no title'}",
                    detail=f"Tech: {', '.join(tech) if tech else 'none'}",
                ))
        except subprocess.TimeoutExpired:
            findings.append(Finding(severity="info", title="httpx timeout"))
        except json.JSONDecodeError:
            pass

        ffuf_outfile = output_dir / "ffuf.json"
        wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        ffuf_cmd = [
            "ffuf", "-u", f"{base_url}FUZZ",
            "-w", wordlist,
            "-of", "json", "-o", str(ffuf_outfile),
            "-mc", "200,204,301,302,307,401,403",
            "-t", "40",
        ]

        try:
            subprocess.run(ffuf_cmd, capture_output=True, text=True, timeout=180)
            output_files.append(ffuf_outfile)

            if ffuf_outfile.exists():
                ffuf_data = json.loads(ffuf_outfile.read_text())
                for r in ffuf_data.get("results", []):
                    findings.append(Finding(
                        severity="notable",
                        title=f"Path found: {r['url']}",
                        detail=f"Status: {r['status']}, Length: {r['length']}",
                    ))
        except subprocess.TimeoutExpired:
            findings.append(Finding(severity="info", title="ffuf timeout"))
        except (json.JSONDecodeError, FileNotFoundError):
            pass

        return PluginResult(
            plugin_name=self.name,
            port=port.number,
            success=True,
            findings=findings,
            output_files=output_files,
        )