"""Tests for security: port scans, ARP spoofing, DNS entropy, cleartext creds."""

import pytest

from noc_pcap_mcp.security import detect_anomalies


def test_detect_anomalies_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        detect_anomalies("does-not-exist.pcap")


def test_detect_port_scan(port_scan_pcap):
    findings = [f for f in detect_anomalies(port_scan_pcap) if f["type"] == "port_scan"]

    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_ip"] == "10.0.3.1"
    assert finding["distinct_targets"] == 25


def test_detect_arp_spoofing(arp_spoof_pcap):
    findings = [f for f in detect_anomalies(arp_spoof_pcap) if f["type"] == "arp_spoofing"]

    assert len(findings) == 1
    finding = findings[0]
    assert finding["ip"] == "10.0.4.1"
    macs = {entry["mac"] for entry in finding["macs"]}
    assert macs == {"aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:66"}


def test_detect_dns_high_entropy_flags_only_the_dga_like_query(dns_entropy_pcap):
    findings = [f for f in detect_anomalies(dns_entropy_pcap) if f["type"] == "dns_high_entropy"]

    assert len(findings) == 1
    assert findings[0]["query"] == "qx7mvz9klp2wrtbn4hjs8f.example.com"


def test_syn_scan_of_port_23_is_not_reported_as_telnet_session(syn_scan_of_port_23_pcap):
    findings = detect_anomalies(syn_scan_of_port_23_pcap)

    assert not any(f["type"] == "cleartext_protocol" for f in findings)


def test_detect_cleartext_credentials(cleartext_credentials_pcap):
    findings = detect_anomalies(cleartext_credentials_pcap)
    by_protocol = {f["protocol"] for f in findings if f["type"] == "cleartext_credential"}

    assert "HTTP Basic Auth" in by_protocol
    assert "HTTP form POST" in by_protocol

    ftp_findings = [f for f in findings if f.get("protocol") == "FTP"]
    assert {f["description"].split()[1] for f in ftp_findings} == {"username", "password"}

    telnet_findings = [f for f in findings if f["type"] == "cleartext_protocol"]
    assert len(telnet_findings) == 1
    assert telnet_findings[0]["protocol"] == "Telnet"


def test_findings_are_sorted_by_severity(cleartext_credentials_pcap):
    findings = detect_anomalies(cleartext_credentials_pcap)
    severities = [f["severity"] for f in findings]
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    assert severities == sorted(severities, key=lambda s: severity_rank[s])
