import argparse
import sys
import time
from pathlib import Path

from superecon.nmap_runner import (
    NmapExecutionError, scan_target, run_full_scan_background,
)
from superecon.trigger_engine import TriggerEngine
from superecon.plugins.registry import registry
from superecon.executor import run_plugins_concurrently, PluginTask
from superecon.summary_writer import write_summary

import superecon.plugins.http_plugin  # noqa: F401
import superecon.plugins.ftp_plugin   # noqa: F401
import superecon.plugins.ssh_plugin   # noqa: F401
import superecon.plugins.smb_plugin   # noqa: F401


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="superecon")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="1-1000")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--show-closed", action="store_true")
    parser.add_argument("--enumerate", action="store_true")
    parser.add_argument("--allow-bruteforce", action="store_true", dest="allow_bruteforce")
    parser.add_argument("--full-scan", action="store_true",
                         help="รัน full port scan (1-65535) แบบ background คู่ขนาน")
    parser.add_argument("-o", "--output", default="./output")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    print(f"[*] เริ่ม scan {args.target} (ports: {args.ports})")
    start_time = time.time()

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

    output_dir = Path(args.output) / args.target
    output_dir.mkdir(parents=True, exist_ok=True)

    # ========== เริ่ม full scan แบบ background (ถ้าสั่ง) ==========
    if args.full_scan:
        quick_ports = {p.number for p in open_ports}
        print(f"\n[*] เริ่ม full port scan (1-65535) แบบ background...")
        run_full_scan_background(args.target, quick_ports, output_dir)
        # ↑ ไม่ต้องเก็บตัวแปร thread ไว้ใช้ต่อ เพราะเป็น daemon thread
        #   ปล่อยให้ทำงานเบื้องหลังไปเรื่อยๆ โปรแกรมหลักไปต่อได้เลย

    results = []
    if args.enumerate:
        print(f"\n[*] เริ่ม enumeration (concurrent)...")

        enabled_flags = {"allow_bruteforce"} if args.allow_bruteforce else set()
        engine = TriggerEngine(Path("config/default.yaml"), enabled_flags=enabled_flags)
        matches = engine.resolve(open_ports)

        if not matches:
            print("[*] ไม่มี trigger ไหนตรงกับ port ที่เจอ")
        else:
            tasks: list[PluginTask] = []
            for match in matches:
                for plugin_name in match.plugin_names:
                    if not registry.has(plugin_name):
                        print(f"  [skip] {plugin_name} ยังไม่ได้ implement (port {match.port.number})")
                        continue
                    service_name = match.port.service.name if match.port.service else "unknown"
                    port_outdir = output_dir / f"{match.port.number}_{service_name}"
                    tasks.append(PluginTask(
                        plugin_name=plugin_name, target_host=args.target,
                        port=match.port, output_dir=port_outdir,
                    ))

            print(f"[*] มอบหมาย {len(tasks)} งานให้ทีมพนักงาน...\n")
            results = run_plugins_concurrently(tasks, max_workers=5, timeout_seconds=120)

            for result in results:
                print(f"[{result.plugin_name}] port {result.port} — {len(result.findings)} finding(s):")
                for finding in result.findings:
                    print(f"  [{finding.severity}] {finding.title}")

    elapsed = time.time() - start_time

    # ========== เขียน summary.md เสมอ (ไม่ว่าจะ enumerate หรือไม่) ==========
    summary_path = write_summary(target, results, elapsed, output_dir)
    print(f"\n[*] เสร็จสิ้นใน {elapsed:.1f} วินาที ดูสรุปที่ {summary_path}")


if __name__ == "__main__":
    main()