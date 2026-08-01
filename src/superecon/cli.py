import argparse
import sys

from superecon.nmap_runner import NmapExecutionError, scan_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="superecon", description="CLI recon automation tool")
    parser.add_argument("-t", "--target", required=True, help="IP หรือ hostname ของ target")
    parser.add_argument("-p", "--ports", default="1-1000", help="ช่วง port (default: 1-1000)")
    parser.add_argument("--timeout", type=int, default=300, help="วินาทีสูงสุดที่รอ nmap")
    # เพิ่มใหม่
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="แสดง closed/filtered port ด้วย (default: แสดงแค่ open)",
    )
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
        print(f"\n[*] Port อื่นๆ ({len(other_ports)}) ไม่มีผลต่อการโจมตี แสดงไว้เพื่อ reference:\n")
        for port in other_ports:
            print(f"  {port.number}/{port.protocol}  [{port.state}]")


if __name__ == "__main__":
    main()