# superecon

CLI recon automation tool ที่เขียนขึ้นเพื่อเตรียมสอบ OSCP/BSCP และแข่ง CTF
รัน port scan → auto-trigger enumeration ตาม service ที่เจอ → สรุปผลเป็น Markdown

## ทำไมสร้างเครื่องมือนี้

Recon เป็นขั้นตอนที่ต้องทำซ้ำๆ ทุกครั้งในทุก target แต่ manual ต้องพิมพ์คำสั่งเดิมๆ
เครื่องมือนี้ automate เฉพาะขั้น recon เบื้องต้น เพื่อประหยัดเวลาไปโฟกัสส่วนที่ต้องคิด
(exploitation, privilege escalation) — ไม่ auto-exploit ใดๆ ทั้งสิ้น

## Installation

git clone https://github.com/yourname/superecon
cd superecon
pip install -e .

## Usage

bash
# Scan พื้นฐาน
superecon -t 10.10.10.5 -p 1-1000

# Scan + auto-enumerate ตาม service ที่เจอ
superecon -t 10.10.10.5 -p 1-1000 --enumerate

# เพิ่ม full port scan แบบ background คู่ขนาน
superecon -t 10.10.10.5 -p 1-1000 --enumerate --full-scan
\`\`\`

## Architecture

- `nmap_runner.py` port scan + XML parsing
- `trigger_engine.py` config-driven rule matching (YAML)
- `plugins/` modular plugin ต่อ service (http/ftp/ssh/smb)
- `executor.py` concurrent execution ด้วย ThreadPoolExecutor
- `summary_writer.py` สรุปผลเป็น Markdown

## Design Decisions

- **ไม่ auto-exploit** ยึดหลัก OSCP exam rules ที่เน้นวัด manual skill ไม่ใช่ automation
- **Config-driven trigger** เพิ่ม service ใหม่แค่แก้ YAML ไม่ต้องแตะ core code
- **ThreadPoolExecutor ไม่ใช่ asyncio** งานเป็น I/O-bound subprocess เหมาะกับ thread มากกว่า
  เข้าใจง่ายกว่าสำหรับ scale ระดับนี้
