# RapidRecon Web Dashboard — Addon Guidebook (v1.0)
## ต่อยอดจาก CLI Engine เดิม — ไม่แตะ Core Logic

> หลักการสำคัญที่สุด: **CLI engine คือ source of truth และยังใช้สอบจริงเหมือนเดิมทุกประการ** เว็บ dashboard เป็นแค่ "หน้าต่างมองผลลัพธ์" ที่ต่อพ่วงเข้ามาทีหลัง ไม่มีวันเข้าไปแทนที่หรือแก้ไข engine

---

## 1. หลักการออกแบบ: Engine/Viewer Separation

```
┌─────────────────────────────────────────────────────────┐
│  ENGINE (เดิม — ใช้สอบจริง, local, ไม่แตะเลย)              │
│  rapidrecon -t <target> -o ./output                       │
│  → เขียนผลลัพธ์เป็นไฟล์ JSON/MD ตามโครงสร้างเดิม             │
└───────────────────────┬─────────────────────────────────┘
                        │ (อ่านไฟล์อย่างเดียว ไม่เรียก subprocess ใดๆ)
┌───────────────────────▼─────────────────────────────────┐
│  VIEWER (ใหม่ — อ่าน output/ แล้ว render เป็นเว็บ)          │
│  ไม่มีสิทธิ์รัน nmap/ffuf/ฯลฯ เอง ไม่มี target input field   │
└─────────────────────────────────────────────────────────┘
```

**ทำไมต้องแยกขาดจากกัน:**
- Viewer ไม่มีความสามารถสั่ง scan ได้เลย → ต่อให้เอาไปวางบน public internet ก็ไม่มีใครใช้เป็นเครื่องมือโจมตีได้ (แก้ปัญหา legal risk ที่คุยกันไว้ตอนแรกทั้งหมด)
- Engine ไม่ต้องรู้จักเว็บเลย → สอบ OSCP/BSCP ใช้ CLI เดิม 100% ไม่มีความเสี่ยงเรื่อง dependency ใหม่ๆ ไปกระทบของเดิม
- ถ้าเว็บพังหรือ deploy ไม่ได้ ไม่กระทบการใช้งานจริงแม้แต่นิดเดียว

---

## 2. สองโหมดการใช้งาน

### โหมด A: Local Dashboard (ใช้งานจริง ระหว่าง lab/CTF ที่บ้าน)
รันบนเครื่องตัวเอง อ่านผลจาก scan ที่เพิ่งทำ เพื่อดูผลสวยกว่า raw JSON/text

```bash
rapidrecon serve --output-dir ./output --port 8080
# เปิด browser ไปที่ localhost:8080 อัตโนมัติ
```

### โหมด B: Public Portfolio Demo (สำหรับโชว์พอร์ต บน cloud)
เว็บ static ที่ deploy จริงบน internet ให้คนอื่นดูได้ แต่ใช้ **demo dataset ที่ scan ไว้ล่วงหน้าแล้ว** (เช่น scan Metasploitable2 ในแล็บตัวเอง) ไม่มีการรัน scan สดบนเว็บเลย

---

## 3. Data Contract ระหว่าง Engine กับ Viewer

เพิ่มไฟล์เดียวในสิ่งที่ Engine เดิมสร้างอยู่แล้ว: `report.json` (รวมทุกอย่างที่มีอยู่แล้วจาก Finding/PluginResult dataclass ให้เป็นไฟล์เดียว)

```json
{
  "target": "10.10.10.5",
  "scan_started": "2026-07-16T14:32:00",
  "scan_duration_seconds": 252,
  "open_ports": [
    {"port": 21, "service": "ftp", "version": "vsftpd 3.0.3"},
    {"port": 80, "service": "http", "version": "Apache 2.4.41"},
    {"port": 445, "service": "smb", "version": "Samba 4.11"}
  ],
  "findings": [
    {
      "port": 21,
      "severity": "critical",
      "title": "Anonymous FTP login allowed",
      "detail": "331 Please specify the password...",
      "plugin": "ftp_plugin"
    },
    {
      "port": 80,
      "severity": "notable",
      "title": "/backup/ directory discovered",
      "detail": "ffuf found status 200",
      "plugin": "http_plugin"
    }
  ],
  "raw_output_files": {
    "80_http": ["whatweb.txt", "httpx.json", "ffuf.json", "nikto.txt"],
    "445_smb": ["enum4linux.json", "smb_shares.txt"]
  }
}
```

**หลักการ:** Engine เดิมมี `Finding`/`PluginResult` dataclass อยู่แล้วจาก guidebook แรก แค่เพิ่ม 1 ฟังก์ชันใน `report/summary_writer.py` ให้ serialize เป็น JSON แทน/เพิ่มเติมจาก markdown ที่มีอยู่แล้ว — ไม่ต้องแก้ core logic ของ plugin ไหนเลย

---

## 4. Tech Stack สำหรับ Web Layer

| Component | เทคโนโลยี | เหตุผล |
|---|---|---|
| Backend (โหมด Local เท่านั้น) | FastAPI, endpoint เดียวคือ `GET /api/scans` อ่านจาก `output/` directory | เบา, ไม่ต้อง database, อ่านไฟล์ตรงๆ |
| Frontend | React (Vite) หรือ Next.js static export | คุณคุ้นเคยอยู่แล้วจากที่คุยกันก่อนหน้า |
| Styling | Tailwind CSS | เร็ว, ไม่ต้องเขียน CSS เยอะ |
| Charts | Recharts | แสดง port/severity distribution เป็นกราฟสวยๆ |
| Syntax highlighting | `react-syntax-highlighter` | โชว์ raw nmap/ffuf output ให้อ่านง่าย |
| Deploy (โหมด B) | Vercel (static export) | ฟรี, ไม่ต้องมี backend เลยเพราะข้อมูลเป็น static JSON ที่ build ไว้ล่วงหน้า |

**จุดสำคัญ:** โหมด B (public demo) **ไม่ต้องมี Oracle Cloud VM เลย** เพราะไม่มี live execution ต้องรัน — เป็น static site ล้วนๆ ที่ fetch `demo-report.json` ที่ build ไว้ในโปรเจกต์ ปลอดภัย 100% และฟรี 100%

---

## 5. โครงสร้างเว็บ Dashboard (หน้าที่ต้องมี)

```
/                     → Target list (การ์ดแสดงแต่ละ target ที่เคย scan)
/scan/:targetId       → รายละเอียด target เดียว
    ├── Overview tab    → open ports table, severity summary chart
    ├── Findings tab    → list ของ Finding ทั้งหมด filter ตาม severity
    └── Raw Output tab  → เลือกดู raw file แต่ละ plugin (syntax highlighted)
```

### Feature ที่ทำให้ portfolio ดูดีเป็นพิเศษ
- **Search/filter ข้าม target หลายตัว** — เช่น "หา target ไหนบ้างที่มี anonymous FTP" (แสดงว่าออกแบบ data model รองรับ query ข้าม scan ได้ ไม่ใช่แค่โชว์ผล 1 scan)
- **Timeline view** — แสดงลำดับเวลาที่แต่ละ plugin เริ่ม/จบ (ใช้ข้อมูลจาก concurrency execution ที่ engine เก็บอยู่แล้ว)
- **Diff view** — เทียบผล quick scan กับ full scan ว่าเจอ port เพิ่มไหม (โชว์ว่าคุณเข้าใจ pipeline design ของตัวเอง ไม่ใช่แค่ทำ CRUD ธรรมดา)

---

## 6. Local Dashboard — รายละเอียด Backend (โหมด A)

`rapidrecon serve` เพิ่มเป็น subcommand ใหม่ในตัว CLI เดิม:

```python
# cli.py เพิ่ม subcommand
@app.command()
def serve(output_dir: Path, port: int = 8080):
    """เปิด local web dashboard อ่านผลจาก output_dir"""
    from rapidrecon.webui.server import start_server
    start_server(output_dir, port)
```

Backend มี endpoint เดียวจริงๆ แค่ไม่กี่ตัว (ไม่ซับซ้อน เพราะ read-only):
```
GET  /api/scans              → list ของทุก target ใน output_dir
GET  /api/scans/{target}     → report.json ของ target นั้น
GET  /api/scans/{target}/raw/{file} → ส่งไฟล์ raw output กลับไปโชว์
```

ไม่มี `POST /scan` endpoint ใดๆ ทั้งสิ้น — **นี่คือกฎเหล็ก** ที่ทำให้ viewer ปลอดภัยแม้จะเผลอเปิดพอร์ตออก network วงบ้าน

---

## 7. Public Portfolio Demo — ขั้นตอน Deploy (โหมด B)

1. เลือก 2-3 scan ที่ทำกับ lab ของตัวเอง (Metasploitable2, DVWA, หรือ HTB retired box ที่ได้รับอนุญาตให้เผยแพร่ writeup ได้) ที่ผลลัพธ์ดูน่าสนใจ (มี finding หลายระดับ severity)
2. **Sanitize ข้อมูล** — เปลี่ยน real IP เป็น placeholder เช่น `demo-target-01.local` ลบข้อมูลที่ trace กลับไปหา infrastructure จริงได้ (สำคัญมากถ้าเป็น HTB box ที่ยัง active อยู่ — ห้าม publish walkthrough box ที่ active เด็ดขาดเพราะผิด HTB ToS)
3. `next build && next export` → ได้ static HTML/JSON ทั้งหมด
4. Push ขึ้น Vercel (connect GitHub repo, auto-deploy ทุกครั้งที่ push)
5. ใส่ลิงก์ demo ใน README ของ repo หลัก (`rapidrecon`) พร้อม screenshot

---

## 8. Roadmap เพิ่มเติม (ต่อจาก Week 4 เดิม)

### Week 5 — Data Layer
- [ ] เพิ่ม `report.json` exporter ใน engine (ใช้ dataclass ที่มีอยู่แล้ว → `json.dumps`)
- [ ] เขียน FastAPI read-only endpoints (โหมด A)
- [ ] ทดสอบว่า `rapidrecon serve` เปิดได้จริง อ่านผล scan เก่าได้ถูกต้อง

### Week 6 — Frontend
- [ ] Setup Next.js + Tailwind, หน้า Target List + Detail page
- [ ] เชื่อม API (โหมด A) แสดงผลจริงจาก scan ที่ทำใน Week 1-4
- [ ] เพิ่ม syntax highlighting สำหรับ raw output tab

### Week 7 — Demo + Deploy
- [ ] เลือก/sanitize demo dataset
- [ ] Build static export, deploy Vercel
- [ ] เขียน README ของทั้งโปรเจกต์ใหม่ให้ครอบคลุมทั้ง CLI + Dashboard พร้อม screenshot/GIF demo

---

## 9. สรุปการแบ่งความรับผิดชอบให้ชัด (กันสับสนตอนเขียนโค้ด)

| คำถาม | คำตอบ |
|---|---|
| สอบ OSCP/BSCP ใช้อะไร | CLI engine เดิมเท่านั้น ไม่แตะเว็บเลย |
| เว็บรัน scan ได้ไหม | โหมด A (local) ได้แค่ "อ่าน" ผลที่ CLI ทำไว้แล้ว ไม่มี trigger scan ผ่านเว็บ |
| เว็บ public มีความเสี่ยงไหม | ไม่มี เพราะเป็น static demo data ล้วนๆ ไม่มี backend execution |
| ถ้าอยากให้เว็บสั่ง scan ได้จริงในอนาคต | ทำได้ แต่ต้องกลับไปคุยเรื่อง target whitelist/auth ตามที่เคยประเมินไว้ตอนแรก — ยังไม่แนะนำสำหรับตอนนี้ |

โปรเจกต์นี้ตอนนี้จึงกลายเป็น **1 engine (CLI) + 2 การนำเสนอผล (local viewer, public demo)** ซึ่งครบทุกเป้าหมายที่คุณตั้งไว้ตั้งแต่ต้น: ใช้สอบได้จริง, ฝึก coding logic (engine), และมี portfolio ที่โชว์ full-stack skill ด้วย (dashboard)
