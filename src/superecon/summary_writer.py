from pathlib import Path
from datetime import datetime

from superecon.dataModel import Target, PluginResult

def write_summary(
    target: Target,
    results: list[PluginResult],
    elapsed_seconds: float,
    output_dir: Path,
) -> Path:
    lines = []
    lines.append(f"Summary for target: {target.host}")
    lines.append(f"Scan completed at: {datetime.now().isoformat()}")
    lines.append(f"Elapsed time: {elapsed_seconds:.2f} seconds")
    lines.append(f"Number of plugins executed: {len(results)}")
    lines.append("")

    open_ports = [p for p in target.ports if p.state == "open"]
    lines.append(f"Number of open ports: {len(open_ports)}")
    lines.append("| Port | Service | Version |")
    lines.append("|---|---|---|")
    for port in open_ports:
        service_name = port.service.name if port.service else "unknown"
        service_version = port.service.version if port.service else "unknown"
        lines.append(f"| {port.portid} | {service_name} | {service_version} |")
    lines.append("")

    finding_by_severity = {"critical": [], "notable": [], "info": []}
    for result in results:
        for finding in result.findings:
            severity = finding.severity if finding.severity in finding_by_severity else "info"
            finding_by_severity[severity].append((result.port, finding))

    lines.append("## Findings")
    lines.append("")

    severity_emoji = {"critical": "🔴", "notable": "🟡", "info": "🔵"}
    for severity in ["critical", "notable", "info"]:
        items = finding_by_severity[severity]
        if not items:
            continue
        for port_num, finding in items:
            emoji = severity_emoji[severity]
            lines.append(f"- {emoji} **{severity.upper()}** (port {port_num}): {finding.title}")
            if finding.detail:
                lines.append(f"  - {finding.detail}")
    lines.append("")

    lines.append("## Plugin Execution Log")
    lines.append("")
    for result in results:
        status = "✅" if result.success else "❌"
        lines.append(f"- {status} `{result.plugin_name}` on port {result.port} "
                      f"({len(result.findings)} finding(s))")

    summary_path = output_dir / "summary.md"
    summary_path.write_text("\n".join(lines))
    return summary_path