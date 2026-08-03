import subprocess
from pathlib import Path


def start_capture(interface: str, output_path: Path) -> subprocess.Popen | None:
    """
    เริ่มอัด network traffic ด้วย tcpdump แบบ background
    คืนค่า Popen object (เอาไว้สั่งหยุดทีหลัง) หรือ None ถ้าเริ่มไม่ได้
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        process = subprocess.Popen(
            ["tcpdump", "-i", interface, "-s", "0", "-w", str(output_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # ↑ DEVNULL คือ "ถังขยะ" ทิ้งข้อความที่ tcpdump จะ print ออกจอ
        #   เราไม่อยากให้ terminal รกด้วย log ของ tcpdump ระหว่าง scan
        print(f"[*] เริ่มอัด packet capture บน interface {interface} → {output_path}")
        return process
    except FileNotFoundError:
        print("[!] ไม่พบ tcpdump — ข้ามการ capture (ยังคง scan ต่อได้ปกติ)")
        return None


def stop_capture(process: subprocess.Popen | None):
    """สั่งหยุด tcpdump ที่กำลังทำงานอยู่ (ถ้ามี)"""
    if process is None:
        return
    process.terminate()
    # ↑ .terminate() คือ "ขอร้องให้หยุดอย่างนุ่มนวล" (ส่งสัญญาณ SIGTERM)
    try:
        process.wait(timeout=5)
        # ↑ รอสูงสุด 5 วินาทีให้ tcpdump หยุดตัวเองเรียบร้อย
        print("[*] หยุด packet capture แล้ว")
    except subprocess.TimeoutExpired:
        process.kill()
        # ↑ ถ้า 5 วินาทีแล้วยังไม่หยุด บังคับปิดเลย (SIGKILL) ไม่ต้องถามอีก
        print("[*] บังคับหยุด packet capture (ไม่ตอบสนองปกติ)")