# RapidRecon — CLI Recon Automation Tool
## Complete Design Guidebook (v1.0)

> เป้าหมายโปรเจกต์: สร้าง CLI tool ที่ทำงานได้จริงในสนามสอบ OSCP/BSCP และ CTF, ย่นเวลา recon ซ้ำๆ, และฝึก coding logic ของตัวเองผ่านการสร้างระบบ concurrency/parsing/plugin architecture ที่แท้จริง — ไม่ใช่แค่เว็บ wrapper

---

## 1. ภาพรวมโปรเจกต์

### 1.1 ชื่อโปรเจกต์ (แนะนำ ใช้เป็น GitHub repo name)
`rapidrecon` หรือ `swiftrecon` — ชื่อสั้น จำง่าย ใช้พิมพ์ใน terminal บ่อยๆ

### 1.2 คำจำกัดความ 1 ประโยค
เครื่องมือ command-line แบบ multi-threaded ที่รับ target (IP/hostname) แล้วทำ port scan → service detection → auto-trigger enumeration tool ที่เหมาะกับ service ที่เจอ → จัดเก็บผลลัพธ์เป็นโครงสร้างไฟล์ที่อ่านง่าย ทั้งหมดรันบนเครื่อง attack เอง ไม่ต้องพึ่ง network ภายนอกใดๆ

### 1.3 หลักการออกแบบ 5 ข้อ (Design Principles)
1. **Local-first** — ไม่มี web server, ไม่มี cloud dependency ระหว่าง scan ทำงานได้แม้ไม่มี internet เลย (ยกเว้นตอน install ครั้งแรก)
2. **No auto-exploitation** — เครื่องมือทำแค่ recon/enumeration เท่านั้น ไม่ยิง exploit อัตโนมัติ (ให้อยู่ในกรอบกฎ OSCP exam rules)
3. **Composable output** — ทุกผลลัพธ์เก็บเป็น plain text/JSON ในโฟลเดอร์ที่มนุษย์เปิดอ่านเองได้ทันที ไม่ต้องพึ่ง tool มา render
4. **Configuration over code** — เพิ่ม trigger rule ใหม่ (เช่น port ใหม่ → tool ใหม่) ทำผ่านไฟล์ config ไม่ต้องแก้ core code
5. **Fail gracefully** — ถ้า tool ตัวหนึ่ง crash/timeout ต้องไม่ทำให้ scan อื่นที่กำลังรันพร้อมกันหยุดไปด้วย

---

## 2. สถาปัตยกรรมระบบ (Architecture)

```
┌──────────────────────────────────────────────────────────┐
│                      CLI Entry Point                       │
│              rapidrecon -t <target> -o <outdir>             │
└───────────────────────────┬──────────────────────────────┘
                            │
                ┌───────────▼────────────┐
                │   Target Orchestrator   │  ← 1 instance ต่อ target
                │  (จัดการ lifecycle ทั้งหมด) │
                └───────────┬────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼────────┐  ┌───────▼────────┐  ┌───────▼────────┐
│ Port Scan Stage │  │  Service Stage  │  │  Report Stage   │
│ (Nmap/RustScan) │→ │ (Trigger Engine)│→ │ (Summary/MD)    │
└─────────────────┘  └────────┬────────┘  └─────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Plugin Registry    │
                    │ (Module ต่อ service) │
                    │ http/smb/ftp/ssh/.. │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │ Concurrency Pool    │
                    │ (ThreadPoolExecutor)│
                    │  รัน plugin พร้อมกัน  │
                    └─────────────────────┘
```

### 2.1 องค์ประกอบหลัก 5 ส่วน

| Component | หน้าที่ |
|---|---|
| **CLI Entry Point** | รับ argument, validate input, เรียก Orchestrator |
| **Target Orchestrator** | ควบคุม pipeline ทั้งหมดต่อ 1 target ตั้งแต่ port scan จนถึง report |
| **Port Scan Stage** | รัน quick scan (top 1000 ports) ก่อน แล้วตามด้วย full scan (`-p-`) พร้อมกันในพื้นหลัง |
| **Trigger Engine** | อ่านผลลัพธ์ port scan แล้ว match กับ config เพื่อตัดสินว่า plugin ไหนควรถูกเรียก |
| **Plugin Registry** | เก็บ mapping ระหว่างชื่อ service → plugin class ที่รับผิดชอบ enumeration |
| **Concurrency Pool** | รัน plugin หลายตัวพร้อมกันโดยจำกัดจำนวน thread ตาม config |

---

## 3. Tech Stack

| Layer | เทคโนโลยี | เหตุผล |
|---|---|---|
| Language | Python 3.11+ | ecosystem ด้าน security เยอะสุด, subprocess/threading ใช้ง่าย |
| CLI framework | `argparse` (built-in) | ไม่ต้องพึ่ง dependency ภายนอก, พอสำหรับ CLI ระดับนี้ |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` | I/O-bound workload (รอ subprocess) เหมาะกับ thread มากกว่า async สำหรับคนเริ่มต้น |
| Config format | YAML (`pyyaml`) | อ่านง่าย, แก้ trigger rule ได้โดยไม่ต้องแตะโค้ด |
| Output parsing | `xml.etree.ElementTree` (สำหรับ Nmap XML), `re` (สำหรับ text output อื่นๆ) | built-in, ไม่ต้องพึ่ง library หนัก |
| Terminal output | `rich` หรือ `colorama` | แสดงผล progress สวยงาม อ่านง่ายระหว่าง scan |
| Logging | `logging` (built-in) | เก็บ log แยกจาก terminal output, debug ง่าย |
| Packaging | `pipx` + `pyproject.toml` | ติดตั้งเป็น global command ได้ (`rapidrecon`) เหมือน tool มาตรฐานอื่นๆ |

**ไม่ใช้:** FastAPI, React, Docker, Redis, Celery, Vercel, Oracle Cloud — เพราะทั้งหมดนี้ไม่จำเป็นสำหรับ local CLI tool

---

## 4. โครงสร้างโปรเจกต์ (Repository Structure)

```
rapidrecon/
├── pyproject.toml
├── README.md
├── config/
│   ├── default.yaml          # trigger rules หลัก
│   └── wordlists.yaml        # path ไปยัง wordlist ที่ใช้ (SecLists ฯลฯ)
├── rapidrecon/
│   ├── __init__.py
│   ├── cli.py                 # argparse entry point
│   ├── orchestrator.py        # Target Orchestrator
│   ├── portscan/
│   │   ├── __init__.py
│   │   ├── nmap_runner.py     # เรียก nmap, parse XML
│   │   └── rustscan_runner.py # เรียก rustscan (quick scan ก่อน)
│   ├── plugins/
│   │   ├── __init__.py
│   │   ├── base.py            # abstract base class ScanPlugin
│   │   ├── registry.py        # plugin registration/lookup
│   │   ├── http_plugin.py     # ffuf, httpx, whatweb, nikto
│   │   ├── smb_plugin.py      # enum4linux-ng, smbclient, nxc
│   │   ├── ftp_plugin.py      # anonymous login check, banner grab
│   │   ├── ssh_plugin.py      # banner grab, algo enum
│   │   └── dns_plugin.py      # dig, dnsrecon (ถ้าเจอ port 53)
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── trigger_engine.py  # match port/service → plugin list
│   │   └── executor.py        # ThreadPoolExecutor wrapper
│   ├── report/
│   │   ├── __init__.py
│   │   └── summary_writer.py  # สร้าง summary.md ท้าย scan
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       └── file_manager.py    # จัดการโครงสร้าง output directory
└── tests/
    ├── test_nmap_parser.py
    ├── test_trigger_engine.py
    └── fixtures/
        └── sample_nmap_output.xml
```

---

## 5. Pipeline การทำงานแบบละเอียด (Execution Flow)

### Phase 1 — Quick Scan (เป้าหมาย: ได้ผลลัพธ์เบื้องต้นใน < 30 วินาที)
```
rustscan -a <target> --ulimit 5000 -- -sV -sC -oX quick.xml
```
- ใช้ RustScan เพื่อหา open port เร็วๆ ก่อน (scan ครบ 65535 port ใน ~15 วินาที)
- ส่งต่อ port ที่เจอให้ Nmap ทำ `-sV -sC` เฉพาะ port เหล่านั้น (เร็วกว่า scan ทุก port ด้วย -sV)

### Phase 2 — Full Scan (รันคู่ขนานในพื้นหลัง ไม่ block Phase 3)
```
nmap -p- -sV --min-rate 1000 <target> -oX full.xml
```
- รันพร้อมกับ Phase 3 เพราะใช้เวลานาน (5-20 นาที) ไม่ควรให้ user รอ
- เมื่อเสร็จ จะ diff ผลกับ quick scan ว่ามี port เพิ่มไหม ถ้ามี trigger plugin เพิ่มอัตโนมัติ

### Phase 3 — Trigger & Enumerate (เริ่มทันทีหลัง Quick Scan เสร็จ)
1. Trigger Engine อ่าน `quick.xml` → ได้ list ของ (port, service, version)
2. Match กับ `config/default.yaml` เพื่อหา plugin ที่ควรรัน
3. ส่ง task ทั้งหมดเข้า ThreadPoolExecutor พร้อมกัน (จำกัดจำนวนตาม `max_concurrent_plugins`)
4. แต่ละ plugin เขียนผลลัพธ์ลงไฟล์ของตัวเองใน `output/<target>/<port>_<service>/`

### Phase 4 — Report (หลัง plugin ทั้งหมดจบ)
- สร้าง `output/<target>/summary.md` รวม finding สำคัญทั้งหมด (open ports, versions, notable findings เช่น anonymous FTP, default creds)

---

## 6. Trigger Engine — Config Schema แบบเต็ม

`config/default.yaml`:
```yaml
concurrency:
  max_concurrent_plugins: 8
  scan_timeout_seconds: 600

triggers:
  - match:
      port: 80
      service: "http|http-proxy"
    plugins: ["http_plugin"]

  - match:
      port: 443
      service: "https|ssl/http"
    plugins: ["http_plugin"]
    extra_args:
      scheme: "https"

  - match:
      port: 445
      service: "microsoft-ds|netbios-ssn"
    plugins: ["smb_plugin"]

  - match:
      port: 21
      service: "ftp"
    plugins: ["ftp_plugin"]

  - match:
      port: 22
      service: "ssh"
    plugins: ["ssh_plugin"]

  - match:
      port: 53
      service: "domain"
    plugins: ["dns_plugin"]

  - match:
      port: [139, 445]
      service: "netbios"
    plugins: ["smb_plugin"]

fallback:
  # port ที่ไม่ match rule ไหนเลย → เก็บ banner ไว้เฉยๆ ไม่ trigger plugin
  action: "banner_grab_only"
```

**หลักการ:** เพิ่ม service ใหม่ = เพิ่ม entry ใน YAML + เขียน plugin ใหม่ 1 ไฟล์ ไม่ต้องแตะ orchestrator/engine เลย

---

## 7. Plugin Interface (Base Class Contract)

`plugins/base.py` ต้องมี interface ที่ทุก plugin implement ตรงกัน:

```python
class ScanPlugin(ABC):
    name: str                    # ชื่อ plugin เช่น "http_plugin"
    required_binaries: list[str] # เช่น ["ffuf", "httpx", "nikto"]

    @abstractmethod
    def run(self, target: str, port: int, output_dir: Path, context: dict) -> PluginResult:
        """รัน enumeration commands ทั้งหมดของ service นี้"""
        ...

    @abstractmethod
    def parse_findings(self, raw_output: str) -> list[Finding]:
        """แปลง raw output เป็น structured Finding สำหรับ summary report"""
        ...
```

**PluginResult** และ **Finding** เป็น dataclass ง่ายๆ:
```python
@dataclass
class Finding:
    severity: str   # "info" | "notable" | "critical"
    title: str
    detail: str

@dataclass
class PluginResult:
    plugin_name: str
    port: int
    success: bool
    findings: list[Finding]
    output_files: list[Path]
```

**ทำไม design แบบนี้:** บังคับให้ทุก plugin คืนค่าแบบเดียวกัน ทำให้ Report Stage รวมผลลัพธ์จากทุก plugin ได้โดยไม่ต้องรู้รายละเอียดภายในของแต่ละ plugin (classic polymorphism use case)

---

## 8. รายละเอียด Plugin แต่ละตัว (MVP Scope)

### 8.1 `http_plugin` (สำคัญที่สุด — เจอบ่อยสุดในทุก box)
คำสั่งที่รันตามลำดับ:
```bash
whatweb http://<target>:<port>/ > whatweb.txt
httpx -u http://<target>:<port>/ -title -status-code -tech-detect -json > httpx.json
ffuf -u http://<target>:<port>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -of json -o ffuf.json
nikto -h http://<target>:<port>/ -o nikto.txt
```
Parsing: อ่าน `ffuf.json` หา status code ที่ไม่ใช่ 403/404 → สร้าง Finding ระดับ "notable" ถ้าเจอ path น่าสนใจ เช่น `/admin`, `/backup`, `/.git`

### 8.2 `smb_plugin`
```bash
enum4linux-ng -A <target> -oJ enum4linux.json
smbclient -L //<target>/ -N > smb_shares.txt
nxc smb <target> --shares > nxc_shares.txt
```
Parsing: ถ้า `smbclient` list share ที่ anonymous access ได้ → Finding "critical"

### 8.3 `ftp_plugin`
```bash
nmap -p21 --script ftp-anon,ftp-syst <target> -oN ftp_nmap.txt
```
ถ้า `ftp-anon` บอกว่า login ได้ → Finding "critical"

### 8.4 `ssh_plugin`
```bash
nmap -p22 --script ssh2-enum-algos,ssh-auth-methods <target> -oN ssh_nmap.txt
```
ส่วนใหญ่เป็น info level (เก็บ version ไว้เทียบ known CVE ทีหลังด้วยมือ)

### 8.5 `dns_plugin`
```bash
dig axfr @<target> <domain_guess> > axfr_attempt.txt
dnsrecon -d <domain_guess> -n <target> > dnsrecon.txt
```

---

## 9. Concurrency Model — ออกแบบแบบเจาะจง

```
main thread
   │
   ├─ ThreadPoolExecutor(max_workers=8)
   │     ├─ Future: http_plugin.run(port=80)
   │     ├─ Future: http_plugin.run(port=443)
   │     ├─ Future: smb_plugin.run(port=445)
   │     └─ Future: ftp_plugin.run(port=21)
   │
   └─ as_completed() loop → เขียน log real-time เมื่อแต่ละ plugin เสร็จ
```

กฎการจัดการ:
- แต่ละ plugin มี `scan_timeout_seconds` ของตัวเอง (จาก config) ถ้าเกิน → kill subprocess ด้วย `subprocess.TimeoutExpired`, บันทึกเป็น Finding "timeout" ไม่ทำให้ thread อื่น hang ตาม
- ใช้ `subprocess.run(..., timeout=X, capture_output=True)` ไม่ใช่ `os.system()` (ป้องกัน shell injection ด้วย เพราะไม่ผ่าน shell interpreter โดยตรง)
- Target/port ถูก validate ก่อนส่งเข้า subprocess เสมอ (whitelist เฉพาะ IPv4/hostname pattern ที่ regex อนุญาต) — ป้องกัน command injection จาก input ที่พิมพ์ผิดพลาดโดยไม่ตั้งใจ

---

## 10. Output Directory Structure

```
output/
└── 10.10.10.5/
    ├── quick_scan.xml
    ├── full_scan.xml
    ├── summary.md                 ← ไฟล์แรกที่เปิดอ่านเสมอ
    ├── 80_http/
    │   ├── whatweb.txt
    │   ├── httpx.json
    │   ├── ffuf.json
    │   └── nikto.txt
    ├── 445_smb/
    │   ├── enum4linux.json
    │   └── smb_shares.txt
    └── 21_ftp/
        └── ftp_nmap.txt
```

`summary.md` ตัวอย่าง:
```markdown
# Recon Summary — 10.10.10.5
Scan started: 2026-07-16 14:32
Scan duration: 4m 12s

## Open Ports
| Port | Service | Version |
|---|---|---|
| 21 | ftp | vsftpd 3.0.3 |
| 80 | http | Apache 2.4.41 |
| 445 | smb | Samba 4.11 |

## Notable Findings
- 🔴 CRITICAL: Anonymous FTP login allowed (port 21)
- 🟡 NOTABLE: /backup/ directory found via ffuf (port 80, status 200)
- 🟡 NOTABLE: SMB share "shared" accessible without auth (port 445)

## Suggested Next Steps (manual)
- ตรวจสอบไฟล์ใน /backup/ ด้วยมือ
- ลอง download ไฟล์จาก anonymous FTP
```

---

## 11. CLI Interface Design

```bash
# scan พื้นฐาน
rapidrecon -t 10.10.10.5 -o ./output

# scan หลาย target พร้อมกัน (จากไฟล์ list)
rapidrecon -l targets.txt -o ./output --max-targets 3

# ระบุ config ที่ custom เอง
rapidrecon -t 10.10.10.5 --config ./my-config.yaml

# skip full scan (เอาแค่ quick + enumeration ตอนรีบ)
rapidrecon -t 10.10.10.5 --quick-only

# verbose mode (debug)
rapidrecon -t 10.10.10.5 -v
```

Flag สำคัญ:
| Flag | ความหมาย |
|---|---|
| `-t / --target` | single target |
| `-l / --list` | ไฟล์ target list |
| `-o / --output` | output directory |
| `--max-targets` | จำนวน target ที่ scan พร้อมกัน |
| `--quick-only` | ข้าม full port scan |
| `--config` | ใช้ config YAML อื่น |
| `-v / --verbose` | แสดง debug log |

---

## 12. Phased Roadmap (เวอร์ชันจริง ใช้เวลาน้อยกว่าเดิมมาก)

### Week 1 — Foundation
- [ ] ตั้ง repo structure ตามข้อ 4
- [ ] เขียน `nmap_runner.py`: รัน subprocess + parse XML เป็น Python object (port, service, version list)
- [ ] เขียน unit test ด้วย sample XML fixture (ไม่ต้องรัน nmap จริงทุกครั้งตอน test)
- [ ] CLI เบื้องต้น: รับ target เดียว, รัน quick scan, print ผลลัพธ์ดิบ

### Week 2 — Trigger Engine + First Plugin
- [ ] เขียน `trigger_engine.py`: อ่าน YAML, match port/service, return plugin list
- [ ] เขียน `base.py` (abstract class) + `registry.py`
- [ ] Implement `http_plugin` ตัวแรกให้ครบ (คำสั่งตามข้อ 8.1)
- [ ] ทดสอบกับ 1 target จริง (เช่น HTB starting point box)

### Week 3 — Concurrency + Plugin เพิ่ม
- [ ] เขียน `executor.py` (ThreadPoolExecutor wrapper) + timeout handling
- [ ] เพิ่ม `smb_plugin`, `ftp_plugin`, `ssh_plugin`
- [ ] ทดสอบ scan target ที่มีหลาย service พร้อมกัน วัดเวลาเทียบกับ manual

### Week 4 — Report + Polish
- [ ] เขียน `summary_writer.py` → generate summary.md
- [ ] เพิ่ม full scan แบบ background (diff กับ quick scan)
- [ ] Packaging ด้วย `pyproject.toml` + `pipx install .`
- [ ] เขียน README + ตัวอย่างการใช้งาน (สำหรับ portfolio)

### หลัง Week 4 (ตามความสนใจ ไม่รีบ)
- เพิ่ม `dns_plugin`, module สำหรับ SNMP/SMTP
- เพิ่ม known-CVE lookup (เทียบ version ที่เจอกับ CVE database แบบ manual trigger ไม่ auto)
- เพิ่ม export เป็น PDF report (ใช้ pdf skill ทีหลังได้)

---

## 13. Testing & Validation Plan

1. **Unit test:** parser functions (Nmap XML → object) ทดสอบด้วย fixture file ไม่ต้องพึ่ง network
2. **Integration test:** รันกับ intentionally vulnerable target ที่ควบคุมได้เอง เช่น Metasploitable2, DVWA, หรือ HTB/VulnHub box ที่มีสิทธิ์ scan ถูกต้อง
3. **Timing benchmark:** เทียบเวลาที่ใช้ recon ด้วยมือ (พิมพ์ command เองทีละตัว) กับใช้ tool — เก็บตัวเลขไว้ใส่ README เป็นหลักฐานว่า tool ช่วยประหยัดเวลาจริง (ข้อมูลนี้มีค่ามากตอนโชว์พอร์ต)

---

## 14. วิธีใช้จริงในสนามสอบ/CTF

- ติดตั้งบนเครื่อง Kali/attack VM ของคุณเองล่วงหน้า **ก่อนวันสอบ** (OSCP อนุญาตให้เตรียม custom script/tool ของตัวเองมาก่อนได้ เพราะเป็น tool ที่คุณเขียนเอง ไม่ใช่ auto-exploit)
- รัน `rapidrecon -t <exam_target_ip> -o ~/exam/target1` ทิ้งไว้เบื้องหลัง แล้วไปทำงาน manual บน target อื่นต่อระหว่างรอ (นี่คือ pattern เดียวกับที่คนสอบผ่าน OSCP ใช้ AutoRecon จริง)
- เปิด `summary.md` เป็นจุดเริ่มต้นเสมอเมื่อกลับมาดู แทนที่จะไล่อ่าน raw output ทุกไฟล์

---

## 15. ข้อควรระวังด้านกฎหมาย/ความปลอดภัย

- ใช้กับ target ที่ตัวเองมีสิทธิ์เท่านั้น (lab ส่วนตัว, HTB/VulnHub/PortSwigger, หรือ exam target ที่ได้รับอนุญาตแล้ว)
- ห้าม hardcode หรือ commit credential/target จริงลง public GitHub repo — ถ้าจะ open-source ให้เก็บเฉพาะ code, ไม่เก็บ scan result หรือ config ที่มี target จริงติดไปด้วย
- Input validation (ข้อ 9) ต้องทำจริงจัง แม้จะใช้คนเดียว เพราะถ้าพลาดพิมพ์ target ผิดเป็นอะไรที่มี shell metacharacter อาจเกิดพฤติกรรมไม่คาดคิดกับ subprocess ได้

---

## สรุป

เอกสารนี้ครอบคลุมตั้งแต่ architecture, tech stack, โครงสร้างไฟล์, config schema, plugin contract, concurrency design, output format, CLI design, ไปจนถึง roadmap 4 สัปดาห์ที่ทำได้จริง — พร้อมเริ่มเขียนโค้ดได้ทันทีตาม Week 1 ในข้อ 12
