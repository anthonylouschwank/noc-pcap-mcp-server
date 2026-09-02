"""Security anomaly detection: port scans, ARP spoofing, DNS entropy, cleartext creds."""

import math
import re
from collections import defaultdict
from typing import Any

from scapy.all import ARP, DNS, DNSQR, IP, TCP, PcapReader

from .pcap_utils import require_file

_PORT_SCAN_DISTINCT_TARGETS_THRESHOLD = 20
_DNS_ENTROPY_THRESHOLD = 3.5
_DNS_MIN_LABEL_LENGTH = 12

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_BASIC_AUTH_RE = re.compile(rb"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+", re.IGNORECASE)
_FORM_PASSWORD_RE = re.compile(rb"(?:password|passwd|pwd)=[^&\s]+", re.IGNORECASE)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _detect_port_scans(file_path: str) -> list[dict[str, Any]]:
    """A source sending SYNs to many distinct host:port pairs, with few or no
    completed handshakes, looks like reconnaissance rather than normal use."""
    targets_by_source: dict[str, set[tuple[str, int]]] = defaultdict(set)
    first_frame_by_source: dict[str, int] = {}

    with PcapReader(file_path) as reader:
        for frame_number, packet in enumerate(reader, start=1):
            if TCP not in packet or IP not in packet:
                continue
            tcp = packet[TCP]
            if tcp.flags.S and not tcp.flags.A:
                src = packet[IP].src
                targets_by_source[src].add((packet[IP].dst, tcp.dport))
                first_frame_by_source.setdefault(src, frame_number)

    findings = []
    for src, targets in targets_by_source.items():
        if len(targets) < _PORT_SCAN_DISTINCT_TARGETS_THRESHOLD:
            continue
        sample = [{"ip": ip, "port": port} for ip, port in sorted(targets)[:10]]
        findings.append(
            {
                "type": "port_scan",
                "severity": "medium",
                "source_ip": src,
                "distinct_targets": len(targets),
                "sample_targets": sample,
                "first_frame": first_frame_by_source[src],
                "description": (
                    f"{src} sent SYN packets to {len(targets)} distinct host:port "
                    "combinations, consistent with a port scan."
                ),
            }
        )
    return findings


def _detect_arp_spoofing(file_path: str) -> list[dict[str, Any]]:
    """The same IP announced by more than one MAC address in ARP traffic is
    the classic ARP spoofing signature."""
    macs_by_ip: dict[str, dict[str, int]] = defaultdict(dict)  # ip -> {mac: first_frame}

    with PcapReader(file_path) as reader:
        for frame_number, packet in enumerate(reader, start=1):
            if ARP not in packet:
                continue
            arp = packet[ARP]
            if arp.psrc == "0.0.0.0":
                continue  # ARP probe: sender has no address yet, nothing to spoof
            macs_by_ip[arp.psrc].setdefault(arp.hwsrc, frame_number)

    findings = []
    for ip, macs in macs_by_ip.items():
        if len(macs) < 2:
            continue
        findings.append(
            {
                "type": "arp_spoofing",
                "severity": "high",
                "ip": ip,
                "macs": [{"mac": mac, "first_frame": frame} for mac, frame in macs.items()],
                "description": (
                    f"{ip} was announced by {len(macs)} different MAC addresses in "
                    "ARP traffic, consistent with ARP spoofing."
                ),
            }
        )
    return findings


def _detect_dns_high_entropy(file_path: str) -> list[dict[str, Any]]:
    """A high Shannon entropy leftmost label on a long-enough query name can
    indicate a DGA (malware domain generation algorithm) or DNS tunneling.
    This is a heuristic, not proof -- legitimate CDNs also use random-looking
    subdomains."""
    findings = []

    with PcapReader(file_path) as reader:
        for frame_number, packet in enumerate(reader, start=1):
            if DNS not in packet or DNSQR not in packet or packet[DNS].qr != 0:
                continue
            qname = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            label = qname.split(".")[0]
            if len(label) < _DNS_MIN_LABEL_LENGTH:
                continue

            entropy = _shannon_entropy(label)
            if entropy < _DNS_ENTROPY_THRESHOLD:
                continue

            findings.append(
                {
                    "type": "dns_high_entropy",
                    "severity": "medium",
                    "frame": frame_number,
                    "query": qname,
                    "entropy_bits_per_char": round(entropy, 2),
                    "description": (
                        f"DNS query for '{qname}' has a high-entropy label "
                        f"({entropy:.2f} bits/char), which can indicate a DGA or "
                        "DNS tunneling -- verify before treating it as malicious."
                    ),
                }
            )
    return findings


def _detect_cleartext_credentials(file_path: str) -> list[dict[str, Any]]:
    """HTTP Basic Auth headers, HTTP form password fields and FTP USER/PASS
    commands sent in plaintext, plus Telnet sessions (inherently cleartext).
    Matching is per-packet (no TCP reassembly), so a credential split across
    TCP segments can be missed."""
    findings = []
    telnet_streams_flagged: set[frozenset] = set()

    with PcapReader(file_path) as reader:
        for frame_number, packet in enumerate(reader, start=1):
            if TCP not in packet or IP not in packet:
                continue
            tcp = packet[TCP]
            src, dst = packet[IP].src, packet[IP].dst
            payload = bytes(tcp.payload)

            if not payload:
                if tcp.sport == 23 or tcp.dport == 23:
                    key = frozenset({(src, tcp.sport), (dst, tcp.dport)})
                    if key not in telnet_streams_flagged:
                        telnet_streams_flagged.add(key)
                        findings.append(
                            {
                                "type": "cleartext_protocol",
                                "severity": "low",
                                "frame": frame_number,
                                "protocol": "Telnet",
                                "source": src,
                                "destination": dst,
                                "description": (
                                    f"Telnet session between {src} and {dst} on port 23 "
                                    "-- Telnet sends everything, including credentials, "
                                    "unencrypted."
                                ),
                            }
                        )
                continue

            if _BASIC_AUTH_RE.search(payload):
                findings.append(
                    {
                        "type": "cleartext_credential",
                        "severity": "critical",
                        "frame": frame_number,
                        "protocol": "HTTP Basic Auth",
                        "source": src,
                        "destination": dst,
                        "description": (
                            f"HTTP Basic Auth credential sent in cleartext from {src} to {dst}."
                        ),
                    }
                )

            if _FORM_PASSWORD_RE.search(payload):
                findings.append(
                    {
                        "type": "cleartext_credential",
                        "severity": "critical",
                        "frame": frame_number,
                        "protocol": "HTTP form POST",
                        "source": src,
                        "destination": dst,
                        "description": (
                            f"A password field was submitted in cleartext from {src} to {dst}."
                        ),
                    }
                )

            if tcp.sport == 21 or tcp.dport == 21:
                if payload.startswith(b"USER ") or payload.startswith(b"PASS "):
                    field = "username" if payload.startswith(b"USER ") else "password"
                    findings.append(
                        {
                            "type": "cleartext_credential",
                            "severity": "critical",
                            "frame": frame_number,
                            "protocol": "FTP",
                            "source": src,
                            "destination": dst,
                            "description": f"FTP {field} sent in cleartext from {src} to {dst}.",
                        }
                    )

    return findings


def detect_anomalies(file_path: str) -> list[dict[str, Any]]:
    """Findings ranked by severity: port scans, ARP spoofing (one IP, multiple
    MACs), high-entropy DNS queries, and credentials sent in cleartext."""
    require_file(file_path)

    findings = [
        *_detect_cleartext_credentials(file_path),
        *_detect_arp_spoofing(file_path),
        *_detect_port_scans(file_path),
        *_detect_dns_high_entropy(file_path),
    ]
    findings.sort(key=lambda finding: _SEVERITY_ORDER.get(finding["severity"], 99))
    return findings
