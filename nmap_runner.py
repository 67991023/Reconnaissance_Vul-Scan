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
