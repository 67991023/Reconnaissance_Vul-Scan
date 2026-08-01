from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# เเยก service จาก port เพราะ port อาจจะมี service หรือไม่ก็ได้ และ service ก็อาจจะมีข้อมูลหลาย field
@dataclass
class Service: # ข้อมูล service ที่เจอบน 1 port เช่น http, ssh, smb
    name: str                  # http
    product: str = ""          # Apache httpd
    version: str = ""          # 2.4.41
    extra_info: str = ""       # Ubuntu

    def full_banner(self) -> str: # รวม field ทั้งหมดเป็น string เดียว
        parts = [self.product, self.version, self.extra_info]
        return " ".join(p for p in parts if p) or self.name


@dataclass
class Port: # แทนข้อมูล 1 port ที่เปิดอยู่บน target
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: Service | None = None # port จะมี service ไหม ถ้ามีจะเก็บข้อมูล service ไว้ใน object Service


@dataclass
class Target:
    # แทนเครื่องดียวที่กำลัง scan อยู่ พร้อมทุก port ที่เจอ
    host: str
    ports: list[Port] = field(default_factory=list) # default_factory ใช้สร้าง list ใหม่ทุกครั้งที่สร้าง Target object
    scan_started: datetime = field(default_factory=datetime.now)

    def get_port(self, number: int) -> Port | None: # คืนค่า Port object ที่ตรงกับเลข port ที่ส่งเข้ามา ถ้าไม่เจอจะคืนค่า None
        # หา Port object จากเลข port
        for p in self.ports:
            if p.number == number:
                return p
        return None


@dataclass
class Finding:
    # ผลลัพธ์ที่น่าสนใจจาก plugin
    severity: str    # "info" | "notable" | "critical"
    title: str
    detail: str = ""

@dataclass
class PluginResult: # ผลลัพธ์การรันของ 1 plugin
    plugin_name: str
    port: int
    success: bool
    findings: list[Finding] = field(default_factory=list)
    output_files: list[Path] = field(default_factory=list)