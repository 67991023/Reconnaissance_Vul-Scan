from superecon.plugins.base import ScanPlugin


class PluginRegistry:
    """
    เก็บ mapping ระหว่างชื่อ plugin (string) กับ class ของมัน
    ใช้ pattern แบบ Singleton-like (มี instance เดียวที่ใช้ร่วมกันทั้งโปรแกรม)
    """

    def __init__(self):
        self._plugins: dict[str, type[ScanPlugin]] = {}

    def register(self, plugin_class: type[ScanPlugin]):
        """ลงทะเบียน plugin class เข้า registry โดยใช้ 'name' attribute ของ class เป็น key"""
        self._plugins[plugin_class.name] = plugin_class

    def get(self, name: str) -> type[ScanPlugin]:
        if name not in self._plugins:
            raise KeyError(f"ไม่พบ plugin ชื่อ '{name}' ใน registry — ตรวจสอบว่า register แล้วหรือยัง")
        return self._plugins[name]

    def all_names(self) -> list[str]:
        return list(self._plugins.keys())


# instance เดียวที่ใช้ร่วมกันทั้งโปรแกรม (module-level singleton)
registry = PluginRegistry()


def register_plugin(plugin_class: type[ScanPlugin]):
    """decorator สำหรับ register plugin แบบสั้นๆ อ่านง่าย"""
    registry.register(plugin_class)
    return plugin_class