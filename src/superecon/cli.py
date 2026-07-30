import argparse
import sys

from superecon.nmap_runner import scan_target, NmapExecutionError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="superecon",
        description="CLI recon automation tool สำหรับ OSCP/BSCP/CTF",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="IP หรือ hostname ของ target ที่จะ scan",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1000",
        help="ช่วง port ที่จะ scan (default: 1-1000)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="จำนวนวินาทีสูงสุดที่รอ nmap ทำงาน",
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
        print("[!] ไม่พบ open port ใดๆ")
        return

    print(f"\n[+] พบ {len(target.ports)} open port(s) บน {target.host}:\n")
    for port in target.ports:
        service_info = port.service.full_banner() if port.service else "unknown"
        print(f"  {port.number}/{port.protocol}  open  {service_info}")


if __name__ == "__main__":
    main()