import argparse
import sys
import time
from pathlib import Path

from superecon.nmap_runner import NmapExecutionError, scan_target
from superecon.trigger_engine import TriggerEngine
from superecon.plugins.registry import registry
from superecon.executor import run_plugins_concurrently, PluginTask

import superecon.plugins.http_plugin  
import superecon.plugins.ftp_plugin   
import superecon.plugins.ssh_plugin   
import superecon.plugins.smb_plugin   


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="superecon")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="1-1000")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--show-closed", action="store_true")
    parser.add_argument("--enumerate", action="store_true")
    parser.add_argument("--allow-bruteforce", action="store_true", dest="allow_bruteforce")
    parser.add_argument("-o", "--output", default="./output")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    print(f"[*] เริ่ม scan {args.target} (ports: {args.ports})")

    try:
        target = scan_target(args.target, ports=args.ports, timeout=args.timeout)
    except NmapExecutionError as e:
        print(f"[!] Scan ล้มเหลว: {e}", file=sys.stderr)
        sys.exit(1)

    if not target.ports:
        print("[!] ไม่พบ port ใดๆ ในผลลัพธ์")
        return

    open_ports = [p for p in target.ports if p.state == "open"]
    other_ports = [p for p in target.ports if p.state != "open"]

    print(f"\n[+] พบ {len(open_ports)} open port(s) บน {target.host}:\n")
    for port in open_ports:
        service_info = port.service.full_banner() if port.service else "unknown"
        print(f"  {port.number}/{port.protocol}  open  {service_info}")

    if args.show_closed and other_ports:
        print(f"\n[*] Port อื่นๆ ({len(other_ports)}):\n")
        for port in other_ports:
            print(f"  {port.number}/{port.protocol}  [{port.state}]")

    if not args.enumerate:
        return

    print(f"\n[*] เริ่ม enumeration (concurrent)...")
    start_time = time.time()   # ← เริ่มจับเวลา (ใช้เทียบ manual ทีหลัง)

    enabled_flags = {"allow_bruteforce"} if args.allow_bruteforce else set()
    engine = TriggerEngine(Path("config/default.yaml"), enabled_flags=enabled_flags)
    matches = engine.resolve(open_ports)

    if not matches:
        print("[*] ไม่มี trigger ไหนตรงกับ port ที่เจอ")
        return

    # ========== สร้าง "รายการใบสั่งงาน" ทั้งหมดก่อน (ยังไม่รันจริง) ==========
    tasks: list[PluginTask] = []
    for match in matches:
        for plugin_name in match.plugin_names:
            if not registry.has(plugin_name):
                print(f"  [skip] {plugin_name} ยังไม่ได้ implement (port {match.port.number})")
                continue

            service_name = match.port.service.name if match.port.service else "unknown"
            port_outdir = Path(args.output) / args.target / f"{match.port.number}_{service_name}"
            tasks.append(PluginTask(
                plugin_name=plugin_name,
                target_host=args.target,
                port=match.port,
                output_dir=port_outdir,
            ))

    print(f"[*] มอบหมาย {len(tasks)} งานให้ทีมพนักงาน (max 5 คนพร้อมกัน)...\n")

    # รันทุกงานพร้อมกันด้วย executor
    results = run_plugins_concurrently(tasks, max_workers=5, timeout_seconds=120)

    for result in results:
        print(f"[{result.plugin_name}] port {result.port} — {len(result.findings)} finding(s):")
        for finding in result.findings:
            print(f"  [{finding.severity}] {finding.title}")

    elapsed = time.time() - start_time
    print(f"\n[*] Enumeration เสร็จใน {elapsed:.1f} วินาที")


if __name__ == "__main__":
    main()