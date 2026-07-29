import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from dataModel import Target, Port, Service


class NmapExecutionError(Exception):
    pass

def run_nmap_scan(target_host: str, ports: str, timeout: int = 300) -> str:
    command = ["nmap", "-sV", "-p", ports, "-oX", "-", target_host]

    try:
        result = subprocess.run( # คำสั่ง nmap ที่จะรัน เป็น string เพื่อกัน shell injection
            command,
            capture_output=True, # เก็บ stdout ไว้ใน result.stdout
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise NmapExecutionError(f"Nmap timeout after {timeout}s on {target_host}") from e
    except FileNotFoundError as e:
        raise NmapExecutionError("nmap binary not found") from e

    if result.returncode != 0:
        raise NmapExecutionError(f"Nmap exited with code {result.returncode}: {result.stderr}")

    return result.stdout


def parse_nmap_xml(xml_output: str) -> Target:
    root = ET.fromstring(xml_output)
    host_element = root.find("host")
    if host_element is None:
        raise ValueError("target down or scan unable to reach target")
    target_host = root.find("host/address").attrib["addr"]
    target = Target(host=target_host)

    ports_element = host_element.find("ports")
    if ports_element is None:
        return target

    for port_element in ports_element.findall("port"):
        port_number = int(port_element.attrib["portid"])
        protocol = port_element.attrib.get("protocol", "tcp")
        state_element = port_element.find("state")
        state = state_element.attrib.get("state", "unknown") if state_element is not None else "unknown"

        if state != "open":
            continue

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