"""Low-level PCAP reading and TCP conversation indexing helpers (scapy-based)."""

from typing import Any


def summarize_capture(file_path: str) -> dict[str, Any]:
    """Duration, packet count, protocol breakdown and top talkers for a capture."""
    raise NotImplementedError(
        "TODO: scapy.PcapReader over file_path -> duration, packet count, "
        "protocol counts, top talker IPs"
    )


def list_conversations(file_path: str) -> list[dict[str, Any]]:
    """Enumerate TCP conversations (4-tuple) with packet/byte counts and timing."""
    raise NotImplementedError(
        "TODO: group packets by (src_ip, src_port, dst_ip, dst_port), assign a "
        "stable stream_id per conversation, return packet/byte counts + start/end time"
    )
