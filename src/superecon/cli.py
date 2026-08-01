import argparse
import sys
from pathlib import Path

from superecon.nmap_runner import NmapExecutionError, scan_target
from superecon.trigger_engine import TriggerEngine
from superecon.plugins.registry import registry

# บรรทัดนี้สำคัญที่สุดในไฟล์ — ต้อง import ให้ decorator @register_plugin
# ทำงาน ถ้าไม่ import ไฟล์นี้เลย registry จะไม่รู้จัก "http_plugin" เลย
import superecon.http_plugin  # noqa: F401
# ↑ # noqa: F401 คือ comment บอก linter (เช่น flake8) ว่า "รู้แล้วว่าไม่ได้
#   ใช้ตัวแปรจาก import นี้ตรงๆ แต่ตั้งใจ import เพื่อ side-effect (register)"
#   ไม่ใส่ก็ได้ แค่ป้องกัน warning เฉยๆ


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="superecon", description="CLI recon automation tool")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="1-1000")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--show-closed", action="store_true")
    parser.add_argument(
        "--enumerate",
        action="store_true",
        help="รัน trigger engine + plugin ต่อจาก port scan อัตโนมัติ",
    )
    parser.add_argument(
        "--allow-bruteforce",
        action="store_true",
        dest="allow_bruteforce",
        help="เปิดให้รัน trigger ที่เป็น brute-force (เช่น SNMP community brute)",
    )
    parser.add_argument("-o", "--output", default="./output", help="โฟลเดอร์เก็บผลลัพธ์")
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

    # ส่วนใหม่: Trigger Engine + Plugin
    if args.enumerate:
        print(f"\n[*] เริ่ม enumeration...")

        enabled_flags = {"allow_bruteforce"} if args.allow_bruteforce else set()
        engine = TriggerEngine(Path("config/default.yaml"), enabled_flags=enabled_flags)
        matches = engine.resolve(open_ports)

        if not matches:
            print("[*] ไม่มี trigger ไหนตรงกับ port ที่เจอ")
            return

        for match in matches:
            for plugin_name in match.plugin_names:

                if not registry.has(plugin_name):
                    print(f"  [skip] {plugin_name} ยังไม่ได้ implement (port {match.port.number})")
                    continue

                plugin_class = registry.get(plugin_name)
                plugin_instance = plugin_class()

                service_name = match.port.service.name if match.port.service else "unknown"
                port_outdir = Path(args.output) / args.target / f"{match.port.number}_{service_name}"

                print(f"  [running] {plugin_name} on port {match.port.number}...")
                result = plugin_instance.run(args.target, match.port, port_outdir)

                if not result.findings:
                    print(f"    ไม่พบ finding ที่น่าสนใจ")
                for finding in result.findings:
                    print(f"    [{finding.severity}] {finding.title}")


if __name__ == "__main__":
    main()