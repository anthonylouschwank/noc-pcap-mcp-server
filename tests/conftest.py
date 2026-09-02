"""Shared pytest fixtures for noc_pcap_mcp tests."""

from pathlib import Path

import pytest
from scapy.all import ARP, DNS, DNSQR, TCP, UDP, Ether, IP, wrpcap

BASE_TIME = 1_700_000_000.0


def _build_packets() -> list:
    pkts = []

    arp_req = Ether(src="aa:aa:aa:aa:aa:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="10.0.0.1", pdst="10.0.0.2", hwsrc="aa:aa:aa:aa:aa:01"
    )
    arp_req.time = BASE_TIME
    pkts.append(arp_req)

    arp_rep = Ether(src="aa:aa:aa:aa:aa:02", dst="aa:aa:aa:aa:aa:01") / ARP(
        op=2, psrc="10.0.0.2", pdst="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:02"
    )
    arp_rep.time = BASE_TIME + 0.001
    pkts.append(arp_rep)

    dns_q = (
        Ether(src="aa:aa:aa:aa:aa:01", dst="aa:aa:aa:aa:aa:02")
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    dns_q.time = BASE_TIME + 0.01
    pkts.append(dns_q)

    client, server = "10.0.0.1", "10.0.0.2"
    cport, sport = 5000, 80

    syn = Ether() / IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="S", seq=100)
    syn.time = BASE_TIME + 0.02
    pkts.append(syn)

    synack = Ether() / IP(src=server, dst=client) / TCP(sport=sport, dport=cport, flags="SA", seq=500, ack=101)
    synack.time = BASE_TIME + 0.025
    pkts.append(synack)

    ack = Ether() / IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="A", seq=101, ack=501)
    ack.time = BASE_TIME + 0.03
    pkts.append(ack)

    data = (
        Ether() / IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="PA", seq=101, ack=501)
        / (b"GET / HTTP/1.1\r\n" * 3)
    )
    data.time = BASE_TIME + 0.04
    pkts.append(data)

    data_retx = (
        Ether() / IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="PA", seq=101, ack=501)
        / (b"GET / HTTP/1.1\r\n" * 3)
    )
    data_retx.time = BASE_TIME + 0.24
    pkts.append(data_retx)

    resp = (
        Ether() / IP(src=server, dst=client) / TCP(sport=sport, dport=cport, flags="A", seq=501, ack=149)
        / (b"HTTP/1.1 200 OK\r\n" * 2)
    )
    resp.time = BASE_TIME + 0.28
    pkts.append(resp)

    return pkts


@pytest.fixture
def sample_pcap(tmp_path: Path) -> str:
    """A synthetic capture: ARP req/reply, one DNS query, and a TCP
    handshake + data + a retransmitted segment between 10.0.0.1:5000 and
    10.0.0.2:80. Built with scapy instead of checked in as a binary file,
    since real captures are gitignored (they may carry sensitive traffic).
    """
    pcap_path = tmp_path / "sample.pcap"
    wrpcap(str(pcap_path), _build_packets())
    return str(pcap_path)


@pytest.fixture
def empty_pcap(tmp_path: Path) -> str:
    pcap_path = tmp_path / "empty.pcap"
    wrpcap(str(pcap_path), [])
    return str(pcap_path)


@pytest.fixture
def zero_window_pcap(tmp_path: Path) -> str:
    """A handshake, then the server advertises window=0 and later recovers
    with a non-zero window and a different ack (so it isn't also read as a
    duplicate ACK)."""
    client, server = "10.0.1.1", "10.0.1.2"
    cport, sport = 6000, 443
    t = BASE_TIME + 100

    syn = Ether() / IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="S", seq=100)
    syn.time = t
    synack = Ether() / IP(src=server, dst=client) / TCP(sport=sport, dport=cport, flags="SA", seq=500, ack=101)
    synack.time = t + 0.05
    ack = Ether() / IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="A", seq=101, ack=501)
    ack.time = t + 0.06

    zero_window = Ether() / IP(src=server, dst=client) / TCP(
        sport=sport, dport=cport, flags="A", seq=501, ack=101, window=0
    )
    zero_window.time = t + 0.10

    recovery = Ether() / IP(src=server, dst=client) / TCP(
        sport=sport, dport=cport, flags="A", seq=501, ack=102, window=4096
    )
    recovery.time = t + 0.40

    pcap_path = tmp_path / "zero_window.pcap"
    wrpcap(str(pcap_path), [syn, synack, ack, zero_window, recovery])
    return str(pcap_path)


@pytest.fixture
def duplicate_ack_pcap(tmp_path: Path) -> str:
    """A handshake, then the client sends the same pure ACK twice in a row."""
    client, server = "10.0.2.1", "10.0.2.2"
    cport, sport = 7000, 443
    t = BASE_TIME + 200

    syn = Ether() / IP(src=client, dst=server) / TCP(sport=cport, dport=sport, flags="S", seq=100)
    syn.time = t
    synack = Ether() / IP(src=server, dst=client) / TCP(sport=sport, dport=cport, flags="SA", seq=500, ack=101)
    synack.time = t + 0.05
    first_ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=cport, dport=sport, flags="A", seq=101, ack=501, window=8192
    )
    first_ack.time = t + 0.06
    duplicate_ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=cport, dport=sport, flags="A", seq=101, ack=501, window=8192
    )
    duplicate_ack.time = t + 0.09

    pcap_path = tmp_path / "duplicate_ack.pcap"
    wrpcap(str(pcap_path), [syn, synack, first_ack, duplicate_ack])
    return str(pcap_path)


@pytest.fixture
def port_scan_pcap(tmp_path: Path) -> str:
    """25 SYNs from one source to 25 distinct ports on one host: a classic
    vertical port scan, above the detector's threshold of 20."""
    scanner, target = "10.0.3.1", "10.0.3.2"
    t = BASE_TIME + 300

    pkts = []
    for i, port in enumerate(range(1000, 1025)):
        pkt = Ether() / IP(src=scanner, dst=target) / TCP(sport=40000 + i, dport=port, flags="S", seq=100 + i)
        pkt.time = t + i * 0.001
        pkts.append(pkt)

    pcap_path = tmp_path / "port_scan.pcap"
    wrpcap(str(pcap_path), pkts)
    return str(pcap_path)


@pytest.fixture
def arp_spoof_pcap(tmp_path: Path) -> str:
    """10.0.4.1 is announced by two different MAC addresses in ARP replies,
    the classic ARP spoofing signature."""
    t = BASE_TIME + 400

    legit_reply = Ether(src="aa:aa:aa:aa:aa:01") / ARP(
        op=2, psrc="10.0.4.1", hwsrc="aa:aa:aa:aa:aa:01", pdst="10.0.4.100"
    )
    legit_reply.time = t

    spoofed_reply = Ether(src="bb:bb:bb:bb:bb:66") / ARP(
        op=2, psrc="10.0.4.1", hwsrc="bb:bb:bb:bb:bb:66", pdst="10.0.4.100"
    )
    spoofed_reply.time = t + 1.0

    pcap_path = tmp_path / "arp_spoof.pcap"
    wrpcap(str(pcap_path), [legit_reply, spoofed_reply])
    return str(pcap_path)


@pytest.fixture
def dns_entropy_pcap(tmp_path: Path) -> str:
    """One normal-looking query and one long, high-entropy (DGA-like) query."""
    t = BASE_TIME + 500

    normal = (
        Ether()
        / IP(src="10.0.5.1", dst="8.8.8.8")
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="www.google.com"))
    )
    normal.time = t

    dga = (
        Ether()
        / IP(src="10.0.5.1", dst="8.8.8.8")
        / UDP(sport=5354, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="qx7mvz9klp2wrtbn4hjs8f.example.com"))
    )
    dga.time = t + 0.1

    pcap_path = tmp_path / "dns_entropy.pcap"
    wrpcap(str(pcap_path), [normal, dga])
    return str(pcap_path)


@pytest.fixture
def cleartext_credentials_pcap(tmp_path: Path) -> str:
    """One packet per cleartext-credential channel: HTTP Basic Auth, an HTTP
    form password field, FTP USER/PASS, and an empty-payload Telnet packet."""
    t = BASE_TIME + 600

    basic_auth = (
        Ether()
        / IP(src="10.0.6.1", dst="10.0.6.2")
        / TCP(sport=50000, dport=80, flags="PA", seq=1, ack=1)
        / (b"GET /admin HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n")
    )
    basic_auth.time = t

    form_post = (
        Ether()
        / IP(src="10.0.6.3", dst="10.0.6.4")
        / TCP(sport=50001, dport=80, flags="PA", seq=1, ack=1)
        / (b"POST /login HTTP/1.1\r\n\r\nusername=alice&password=hunter2")
    )
    form_post.time = t + 0.1

    ftp_user = (
        Ether()
        / IP(src="10.0.6.5", dst="10.0.6.6")
        / TCP(sport=50002, dport=21, flags="PA", seq=1, ack=1)
        / b"USER alice\r\n"
    )
    ftp_user.time = t + 0.2

    ftp_pass = (
        Ether()
        / IP(src="10.0.6.5", dst="10.0.6.6")
        / TCP(sport=50002, dport=21, flags="PA", seq=13, ack=1)
        / b"PASS hunter2\r\n"
    )
    ftp_pass.time = t + 0.3

    telnet = Ether() / IP(src="10.0.6.7", dst="10.0.6.8") / TCP(sport=50003, dport=23, flags="A", seq=1, ack=1)
    telnet.time = t + 0.4

    pcap_path = tmp_path / "cleartext_credentials.pcap"
    wrpcap(str(pcap_path), [basic_auth, form_post, ftp_user, ftp_pass, telnet])
    return str(pcap_path)


def _build_jsonrpc_stream(client: str, server: str, cport: int, sport: int, t: float, messages):
    """messages: list of (sender, delay, json_text) -- sender is "client" or
    "server". Builds one TCP packet per message with correctly incrementing
    per-direction seq numbers."""
    next_seq = {"client": 1, "server": 1000}
    pkts = []

    for sender, delay, json_text in messages:
        payload = json_text.encode("utf-8")
        seq = next_seq[sender]
        if sender == "client":
            pkt = (
                Ether()
                / IP(src=client, dst=server)
                / TCP(sport=cport, dport=sport, flags="PA", seq=seq, ack=1)
                / payload
            )
        else:
            pkt = (
                Ether()
                / IP(src=server, dst=client)
                / TCP(sport=sport, dport=cport, flags="PA", seq=seq, ack=1)
                / payload
            )
        pkt.time = t + delay
        pkts.append(pkt)
        next_seq[sender] = seq + len(payload)

    return pkts


@pytest.fixture
def jsonrpc_pcap(tmp_path: Path) -> str:
    """A minimal MCP-style JSON-RPC lifecycle: initialize request/response,
    an initialized notification, and one tools/call request/response."""
    t = BASE_TIME + 700
    messages = [
        ("client", 0.00, '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'),
        ("server", 0.01, '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}\n'),
        ("client", 0.02, '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'),
        ("client", 0.03, '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"foo"}}\n'),
        ("server", 0.04, '{"jsonrpc":"2.0","id":2,"result":{"content":[]}}\n'),
    ]
    pkts = _build_jsonrpc_stream("10.0.7.1", "10.0.7.2", 55000, 9000, t, messages)

    pcap_path = tmp_path / "jsonrpc.pcap"
    wrpcap(str(pcap_path), pkts)
    return str(pcap_path)


@pytest.fixture
def jsonrpc_malformed_tail_pcap(tmp_path: Path) -> str:
    """One valid request followed by a segment that isn't valid JSON."""
    t = BASE_TIME + 800
    messages = [
        ("client", 0.00, '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'),
        ("client", 0.01, "not-json-at-all"),
    ]
    pkts = _build_jsonrpc_stream("10.0.8.1", "10.0.8.2", 56000, 9001, t, messages)

    pcap_path = tmp_path / "jsonrpc_malformed.pcap"
    wrpcap(str(pcap_path), pkts)
    return str(pcap_path)
