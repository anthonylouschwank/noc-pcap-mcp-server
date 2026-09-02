"""Low-level PCAP reading and TCP conversation indexing helpers (scapy-based)."""

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, PcapReader

_TOP_TALKERS_LIMIT = 5


def _require_file(file_path: str) -> None:
    if not Path(file_path).is_file():
        raise FileNotFoundError(f"Capture file not found: {file_path}")


def iso_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _classify_protocol(packet: Any) -> str:
    if ARP in packet:
        return "ARP"
    if DNS in packet:
        return "DNS"
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if IPv6 in packet:
        return "IPv6"
    if IP in packet:
        return "IP"
    return "Other"


def summarize_capture(file_path: str) -> dict[str, Any]:
    """Duration, packet count, protocol breakdown and top talkers for a capture."""
    _require_file(file_path)

    packet_count = 0
    first_time: float | None = None
    last_time: float | None = None
    protocol_counts: dict[str, int] = defaultdict(int)
    bytes_by_ip: dict[str, int] = defaultdict(int)
    packets_by_ip: dict[str, int] = defaultdict(int)

    with PcapReader(file_path) as reader:
        for packet in reader:
            packet_count += 1
            t = float(packet.time)
            first_time = t if first_time is None else min(first_time, t)
            last_time = t if last_time is None else max(last_time, t)

            protocol_counts[_classify_protocol(packet)] += 1

            src_ip = None
            if IP in packet:
                src_ip = packet[IP].src
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
            elif ARP in packet:
                src_ip = packet[ARP].psrc

            if src_ip:
                bytes_by_ip[src_ip] += len(packet)
                packets_by_ip[src_ip] += 1

    if packet_count == 0 or first_time is None or last_time is None:
        raise ValueError(f"Capture has no packets: {file_path}")

    top_talkers = sorted(bytes_by_ip.items(), key=lambda item: item[1], reverse=True)
    top_talkers = top_talkers[:_TOP_TALKERS_LIMIT]

    return {
        "file_path": file_path,
        "packet_count": packet_count,
        "start_time": iso_timestamp(first_time),
        "end_time": iso_timestamp(last_time),
        "duration_seconds": round(last_time - first_time, 6),
        "protocol_counts": dict(protocol_counts),
        "top_talkers": [
            {"ip": ip, "packets": packets_by_ip[ip], "bytes": total_bytes}
            for ip, total_bytes in top_talkers
        ],
    }


def list_conversations(file_path: str) -> list[dict[str, Any]]:
    """Enumerate TCP conversations with packet/byte counts and timing.

    Conversations are grouped by the unordered pair of (ip, port) endpoints
    and numbered by the order they first appear in the capture (stream_id
    "0", "1", ...), similar to Wireshark's tcp.stream index.
    """
    _require_file(file_path)

    stream_id_by_key: dict[frozenset[tuple[str, int]], str] = {}
    stats: dict[str, dict[str, Any]] = {}

    with PcapReader(file_path) as reader:
        for packet in reader:
            if TCP not in packet:
                continue
            if IP in packet:
                src_ip, dst_ip = packet[IP].src, packet[IP].dst
            elif IPv6 in packet:
                src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
            else:
                continue

            tcp = packet[TCP]
            endpoint_a = (src_ip, tcp.sport)
            endpoint_b = (dst_ip, tcp.dport)
            key = frozenset((endpoint_a, endpoint_b))
            t = float(packet.time)

            if key not in stream_id_by_key:
                stream_id = str(len(stream_id_by_key))
                stream_id_by_key[key] = stream_id
                stats[stream_id] = {
                    "stream_id": stream_id,
                    "endpoint_a": {"ip": endpoint_a[0], "port": endpoint_a[1]},
                    "endpoint_b": {"ip": endpoint_b[0], "port": endpoint_b[1]},
                    "packet_count": 0,
                    "byte_count": 0,
                    "start_time": t,
                    "end_time": t,
                }

            entry = stats[stream_id_by_key[key]]
            entry["packet_count"] += 1
            entry["byte_count"] += len(packet)
            entry["start_time"] = min(entry["start_time"], t)
            entry["end_time"] = max(entry["end_time"], t)

    conversations = []
    for entry in stats.values():
        start, end = entry["start_time"], entry["end_time"]
        conversations.append(
            {
                **entry,
                "start_time": iso_timestamp(start),
                "end_time": iso_timestamp(end),
                "duration_seconds": round(end - start, 6),
            }
        )

    return conversations


def get_conversation_packets(
    file_path: str, stream_id: str
) -> tuple[dict[str, Any], dict[str, Any], list[tuple[int, Any]]]:
    """Endpoints and time-ordered (frame_number, packet) pairs for one TCP
    conversation, identified by the stream_id produced by list_conversations.

    frame_number is the packet's 1-based position in the whole capture
    (matching Wireshark's "No." column), so callers can cite it as evidence.
    """
    _require_file(file_path)

    stream_id_by_key: dict[frozenset[tuple[str, int]], str] = {}
    endpoints_by_stream: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    matching_packets: list[tuple[int, Any]] = []

    with PcapReader(file_path) as reader:
        for frame_number, packet in enumerate(reader, start=1):
            if TCP not in packet:
                continue
            if IP in packet:
                src_ip, dst_ip = packet[IP].src, packet[IP].dst
            elif IPv6 in packet:
                src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
            else:
                continue

            tcp = packet[TCP]
            endpoint_a = (src_ip, tcp.sport)
            endpoint_b = (dst_ip, tcp.dport)
            key = frozenset((endpoint_a, endpoint_b))

            if key not in stream_id_by_key:
                sid = str(len(stream_id_by_key))
                stream_id_by_key[key] = sid
                endpoints_by_stream[sid] = (
                    {"ip": endpoint_a[0], "port": endpoint_a[1]},
                    {"ip": endpoint_b[0], "port": endpoint_b[1]},
                )

            if stream_id_by_key[key] == stream_id:
                matching_packets.append((frame_number, packet))

    if stream_id not in endpoints_by_stream:
        raise ValueError(f"No TCP conversation with stream_id={stream_id!r} in {file_path}")

    endpoint_a, endpoint_b = endpoints_by_stream[stream_id]
    return endpoint_a, endpoint_b, matching_packets
