from pathlib import Path
import pytest

from superecon.nmap_runner import parse_nmap_xml


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_nmap_output.xml"


@pytest.fixture # decorator บอก pytest ว่าฟังก์ชันนี้เป็น fixture ที่สามารถใช้ใน test function อื่น ๆ ได้
def sample_xml() -> str:
    """pytest fixture ฟังก์ชันนี้จะถูกเรียกอัตโนมัติเมื่อ test function ที่รับ argument ชื่อ 'sample_xml'"""
    return FIXTURE_PATH.read_text()


def test_parse_returns_correct_host(sample_xml):
    target = parse_nmap_xml(sample_xml)
    assert target.host == "10.10.10.99"


def test_parse_only_includes_open_ports(sample_xml):
    target = parse_nmap_xml(sample_xml)
    port_numbers = [p.number for p in target.ports]

    assert 22 in port_numbers
    assert 80 in port_numbers
    assert 139 not in port_numbers


def test_parse_extracts_service_details(sample_xml):
    target = parse_nmap_xml(sample_xml)
    ssh_port = target.get_port(22)

    assert ssh_port is not None
    assert ssh_port.service.name == "ssh"
    assert ssh_port.service.product == "OpenSSH"
    assert ssh_port.service.version == "8.2p1"


def test_parse_empty_ports_raises_no_error():
    xml_no_ports = """<?xml version="1.0"?>
    <nmaprun><host><address addr="10.10.10.1" addrtype="ipv4"/></host></nmaprun>"""
    target = parse_nmap_xml(xml_no_ports)
    assert target.host == "10.10.10.1"
    assert target.ports == []


def test_parse_missing_host_raises_value_error():
    xml_no_host = '<?xml version="1.0"?><nmaprun></nmaprun>'
    with pytest.raises(ValueError):
        parse_nmap_xml(xml_no_host)