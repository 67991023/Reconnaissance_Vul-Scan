import subprocess
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

from superecon.dataModel import Target, Port, Service


class NmapExecutionError(Exception):
    """Custom exception — รวม error ทุกแบบที่เกิดจาก nmap ไว้ในชนิดเดียว
    ทำให้โค้ดที่เรียกใช้ (cli.py) จับ error ได้ง่ายด้วย except เดียว"""
    pass


def run_nmap_scan(target_host: str, ports: str = "1-1000", timeout: int = 300) -> str:
    """
    รัน nmap ผ่าน subprocess แล้วคืนค่า XML string ดิบ
    -Pn = ข้าม ping ก่อน scan (target หลายที่ block ICMP แต่ port ยังใช้งานได้จริง)
    -oX - = สั่งให้ nmap พ่น XML ออกทาง stdout แทนเขียนไฟล์
    """
    command = ["nmap", "-sV", "-Pn", "-p", ports, "-oX", "-", target_host]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise NmapExecutionError(f"Nmap timeout after {timeout}s on {target_host}") from e
    except FileNotFoundError as e:
        raise NmapExecutionError("nmap binary not found — ตรวจสอบว่าติดตั้งแล้วหรือยัง") from e

    if result.returncode != 0:
        raise NmapExecutionError(f"Nmap exited with code {result.returncode}: {result.stderr}")

    return result.stdout


def parse_nmap_xml(xml_string: str) -> Target:
    """
    แปลง Nmap XML string เป็น Target object
    เก็บทุก port ไว้ทุก state (open/closed/filtered) — ไม่กรองออก
    ให้ผู้เรียกใช้ (trigger_engine, cli) เป็นคนกรองเอาเฉพาะ open เอง
    """
    root = ET.fromstring(xml_string)

    host_element = root.find("host")
    if host_element is None:
        # ดึงข้อมูลเพิ่มเติมจาก XML เพื่อ debug ง่ายขึ้น
        # (ช่วยแยกว่าเป็นปัญหา ping-block หรือ target/VPN down จริง)
        runstats = root.find("runstats")
        hosts_summary = ""
        if runstats is not None:
            hosts_el = runstats.find("hosts")
            if hosts_el is not None:
                hosts_summary = (
                    f" (up={hosts_el.attrib.get('up')}, "
                    f"down={hosts_el.attrib.get('down')}, "
                    f"total={hosts_el.attrib.get('total')})"
                )
        raise ValueError(
            f"ไม่พบ <host> element ใน nmap XML{hosts_summary} — "
            f"เช็ค VPN/routing ก่อน แล้วลองรัน nmap ตรงๆ ดู raw output"
        )

    address_element = host_element.find("address")
    host_ip = address_element.attrib.get("addr", "unknown")
    target = Target(host=host_ip)

    ports_element = host_element.find("ports")
    if ports_element is None:
        return target   # ไม่มี port element เลย (เช่น firewall block หมด) — ยัง return ได้ปกติ

    for port_element in ports_element.findall("port"):
        port_number = int(port_element.attrib["portid"])
        protocol = port_element.attrib.get("protocol", "tcp")

        state_element = port_element.find("state")
        state = state_element.attrib.get("state", "unknown") if state_element is not None else "unknown"

        service_element = port_element.find("service")
        service = None
        if service_element is not None:
            service = Service(
                name=service_element.attrib.get("name", ""),
                product=service_element.attrib.get("product", ""),
                version=service_element.attrib.get("version", ""),
                extra_info=service_element.attrib.get("extrainfo", ""),
            )

        target.ports.append(Port(number=port_number, protocol=protocol, state=state, service=service))

    return target


def scan_target(target_host: str, ports: str = "1-1000", timeout: int = 300) -> Target:
    """Entry point หลักที่ไฟล์อื่นเรียกใช้ — รวม run + parse ให้เสร็จในทีเดียว"""
    xml_output = run_nmap_scan(target_host, ports=ports, timeout=timeout)
    return parse_nmap_xml(xml_output)


def run_full_scan_background(
    target_host: str,
    quick_scan_ports: set[int],
    output_dir: Path,
    timeout: int = 900,
) -> threading.Thread:
    """
    รัน full port scan (1-65535) แบบ background — ไม่บล็อกโปรแกรมหลัก
    เมื่อเสร็จแล้ว diff กับผลจาก quick scan ว่ามี port เพิ่มไหม
    เขียนผลลง output_dir/full_scan_diff.txt

    quick_scan_ports: set ของเลข port ที่ quick scan เจอไปแล้ว (เอาไว้เทียบ)
    return: Thread object (เป็น daemon — ปิดตามโปรแกรมหลักอัตโนมัติถ้าโปรแกรมจบก่อน)
    """

    def _background_task():
        try:
            xml_output = run_nmap_scan(target_host, ports="1-65535", timeout=timeout)
            full_target = parse_nmap_xml(xml_output)
            full_open_ports = {p.number for p in full_target.ports if p.state == "open"}

            new_ports = full_open_ports - quick_scan_ports
            # ↑ set difference — เอาเฉพาะ port ที่มีใน full scan แต่ไม่มีใน quick scan

            report_path = output_dir / "full_scan_diff.txt"
            if new_ports:
                lines = [f"[+] Full scan เจอ port เพิ่มเติม {len(new_ports)} ตัว:"]
                for port_num in sorted(new_ports):
                    lines.append(f"  - {port_num}/tcp")
                report_path.write_text("\n".join(lines))
                print(f"\n[!] [background] เจอ port เพิ่ม {len(new_ports)} ตัวจาก full scan — ดู {report_path}")
            else:
                report_path.write_text("[*] Full scan ไม่เจอ port เพิ่มเติมจาก quick scan")
        except Exception as e:
            print(f"\n[!] [background] full scan ล้มเหลว: {e}")

    thread = threading.Thread(target=_background_task, daemon=True)
    thread.start()
    return thread