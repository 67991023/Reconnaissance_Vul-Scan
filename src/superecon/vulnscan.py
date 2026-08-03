import json
import subprocess
from pathlib import Path

from superecon.dataModel import Finding


# tag พวกนี้คือ "แค่ตรวจสอบ" ไม่มีการยิง exploit จริงฝังอยู่ในตัว template
# ปลอดภัยกว่าเปิดทุก template แบบไม่เลือก (บาง template อาจมี exploit PoC จริง)
SAFE_TAGS_DEFAULT = "cve,exposure,misconfig,default-login"


def build_nuclei_command(
    target_url: str,
    outdir: Path,
    severity: str = "critical,high",
    intrusive: bool = False,
) -> list[str]:
    """สร้าง command list สำหรับรัน nuclei (ยังไม่รันจริง แค่เตรียมคำสั่งไว้)"""
    cmd = [
        "nuclei", "-u", target_url,
        "-severity", severity,
        "-silent",
        "-jsonl", "-o", str(outdir / "nuclei.jsonl"),
    ]
    if not intrusive:
        cmd += ["-tags", SAFE_TAGS_DEFAULT]
        # ↑ ถ้าไม่เปิด intrusive mode จำกัดแค่ tag ที่ตรวจสอบอย่างเดียว
    return cmd


def ask_confirmation(target_url: str, severity: str, intrusive: bool) -> bool:
    """ถามผู้ใช้ก่อนยิงจริง — คืนค่า True ถ้ายืนยัน, False ถ้ายกเลิก"""
    print(f"\n[!] กำลังจะรัน vulnerability scan กับ {target_url}")
    print(f"    Severity: {severity} | Intrusive mode: {'เปิด' if intrusive else 'ปิด'}")
    answer = input("    ยืนยันการรัน? พิมพ์ yes เพื่อดำเนินการต่อ: ").strip().lower()
    return answer == "yes"


def run_vulnscan(
    target_url: str,
    outdir: Path,
    severity: str = "critical,high",
    intrusive: bool = False,
    timeout: int = 300,
    skip_confirm: bool = False,
) -> list[Finding]:
    """
    รัน nuclei จริง คืนค่าเป็น list ของ Finding
    skip_confirm=True ใช้เฉพาะตอน unit test เท่านั้น ห้ามใช้ในการใช้งานจริง
    """
    outdir.mkdir(parents=True, exist_ok=True)

    if not skip_confirm:
        if not ask_confirmation(target_url, severity, intrusive):
            print("    [*] ยกเลิกการทำงาน")
            return []

    cmd = build_nuclei_command(target_url, outdir, severity, intrusive)
    findings: list[Finding] = []

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        findings.append(Finding(severity="info", title="Nuclei scan timeout"))
        return findings
    except FileNotFoundError:
        findings.append(Finding(severity="info", title="nuclei binary not found — ข้าม vuln scan"))
        return findings

    jsonl_path = outdir / "nuclei.jsonl"
    if not jsonl_path.exists():
        return findings   # ไม่มีไฟล์ผลลัพธ์ = ไม่เจออะไรเลย ไม่ใช่ error

    for line in jsonl_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        # ↑ nuclei -jsonl พ่นผลลัพธ์ทีละบรรทัด (JSON Lines) เหมือน httpx ที่คุยกันไว้ก่อนหน้า

        info = data.get("info", {})
        findings.append(Finding(
            severity=info.get("severity", "info"),
            title=info.get("name", "Unknown finding"),
            detail=f"Template: {data.get('template-id', '?')} | Matched: {data.get('matched-at', '?')}",
        ))

    return findings