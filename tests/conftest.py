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
