import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from superecon.dataModel import Target, Port, Service


class NmapExecutionError(Exception):
    pass


def run_nmap_scan(target_host: str, ports: str = "1-1000", timeout: int = 300) -> str:
    # เพิ่ม -Pn
    command = ["nmap", "-sV", "-Pn", "-p", ports, "-oX", "-", target_host]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise NmapExecutionError(f"Nmap timeout after {timeout}s on {target_host}") from e
    except FileNotFoundError as e:
        raise NmapExecutionError("nmap binary not found — ตรวจสอบว่าติดตั้งแล้วหรือยัง") from e

    if result.returncode != 0:
        raise NmapExecutionError(f"Nmap exited with code {result.returncode}: {result.stderr}")

    return result.stdout


def parse_nmap_xml(xml_string: str) -> Target:
    root = ET.fromstring(xml_string)

    host_element = root.find("host")
    if host_element is None:
        # error message ละเอียดขึ้น
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
        return target

    for port_element in ports_element.findall("port"):
        port_number = int(port_element.attrib["portid"])
        protocol = port_element.attrib.get("protocol", "tcp")

        state_element = port_element.find("state")
        state = state_element.attrib.get("state", "unknown") if state_element is not None else "unknown"

        # ลบ "if state != 'open': continue" ออก — เก็บทุก state ไว้

        service_element = port_element.find("service")
        service = None
        if service_element is not None:
            print(f"DEBUG: service_element.attrib = {service_element.attrib}")
            service = Service(
                name=service_element.attrib.get("name", ""),
                product=service_element.attrib.get("product", ""),
                version=service_element.attrib.get("version", ""),
                extra_info=service_element.attrib.get("extrainfo", ""),
            )

        target.ports.append(Port(number=port_number, protocol=protocol, state=state, service=service))

    return target


def scan_target(target_host: str, ports: str = "1-1000", timeout: int = 300) -> Target:
    xml_output = run_nmap_scan(target_host, ports=ports, timeout=timeout)
    return parse_nmap_xml(xml_output)