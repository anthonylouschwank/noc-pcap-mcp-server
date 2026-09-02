"""Security anomaly detection: port scans, ARP spoofing, DNS entropy, cleartext creds."""

from typing import Any


def detect_anomalies(file_path: str) -> list[dict[str, Any]]:
    """Findings ranked by severity: port scans, ARP spoofing (one IP, multiple
    MACs), high-entropy DNS queries, and credentials sent in cleartext."""
    raise NotImplementedError(
        "TODO: port scan = many SYNs, few/no completed handshakes, across many "
        "ports/hosts from one source; ARP spoofing = same IP mapped to >1 MAC in "
        "ARP replies; DNS entropy = Shannon entropy of queried labels; cleartext "
        "creds = HTTP Basic Auth, FTP USER/PASS, Telnet, unencrypted form posts"
    )
