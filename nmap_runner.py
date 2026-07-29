import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from dataModel import Target, Port, Service

result = subprocess.run(
    ["nmap", "-sV", "-p", ports, "-oX", "-", target_host], # คำสั่ง nmap ที่จะรัน เป็น string เพื่อกัน shell injection
    capture_output=True, # เก็บ stdout ไว้ใน result.stdout
    text=True,
    timeout=300,
)