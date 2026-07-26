from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Service: # ข้อมูล service ที่เจอบน 1 port เช่น http, ssh, smb
    name: str                  # http
    product: str = ""          # Apache httpd
    version: str = ""          # 2.4.41
    extra_info: str = ""       # Ubuntu

    def full_banner(self) -> str: # รวม field ทั้งหมดเป็น string เดียว
        parts = [self.product, self.version, self.extra_info]
        return " ".join(p for p in parts if p == True) or self.name
