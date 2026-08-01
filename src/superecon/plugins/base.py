from abc import ABC, abstractmethod
from pathlib import Path

from superecon.dataModel import Port, PluginResult


class ScanPlugin(ABC):
    """
    Base class ที่ทุก plugin ต้อง inherit
    บังคับว่าต้อง implement 'run' method เสมอ
    """
    name: str = "base_plugin"          # class attribute — plugin ลูกต้อง override ค่านี้
    required_binaries: list[str] = []   # เช่น ["ffuf", "httpx"] — ใช้เช็คก่อนรันว่ามี tool ติดตั้งไหม

    @abstractmethod
    def run(self, target_host: str, port: Port, output_dir: Path) -> PluginResult:
        """
        Method หลักที่ plugin ลูกทุกตัวต้อง implement
        รับ target + port ที่ trigger engine ส่งมา แล้วคืนผลลัพธ์เป็น PluginResult เสมอ
        """
        raise NotImplementedError # เเจ้งคำเตือน

    def check_binaries_installed(self) -> list[str]:
        """
        Helper method (ไม่ใช่ abstract มี default implementation ให้ใช้ได้เลย)
        คืน list ของ binary ที่ยังไม่ได้ติดตั้ง (ถ้า list ว่าง = ติดตั้งครบ)
        """
        import shutil
        missing = [b for b in self.required_binaries if shutil.which(b) is None]
        return missing