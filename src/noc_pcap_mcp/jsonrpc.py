"""TCP payload reassembly and JSON-RPC message classification for one conversation."""

import json
import re
from typing import Any

from scapy.all import IP, IPv6, TCP

from .pcap_utils import get_conversation_packets, iso_timestamp

_NOT_WHITESPACE = re.compile(r"\S")


def _sender_key(packet: Any) -> tuple[Any, int]:
    if IP in packet:
        ip = packet[IP].src
    elif IPv6 in packet:
        ip = packet[IPv6].src
    else:
        ip = None
    return (ip, packet[TCP].sport)


def _reassemble_direction(
    frames: list[tuple[int, Any]], sender_key: tuple[Any, int]
) -> tuple[str, list[dict[str, Any]]]:
    """Concatenate one direction's payload bytes, ordered and deduped by TCP
    seq number (drops retransmissions), decoded as UTF-8 text. Returns the
    text plus, for each contributing segment, its [start, end) offset into
    that text and the frame_number/time it came from -- so a later JSON
    message's start offset can be traced back to the packet that carried it.
    """
    segments_by_seq: dict[int, tuple[int, float, bytes]] = {}

    for frame_number, packet in frames:
        if _sender_key(packet) != sender_key:
            continue
        payload = bytes(packet[TCP].payload)
        if not payload:
            continue
        seq = packet[TCP].seq
        if seq not in segments_by_seq:
            segments_by_seq[seq] = (frame_number, float(packet.time), payload)

    ordered = [segments_by_seq[seq] for seq in sorted(segments_by_seq)]

    text_parts = []
    segment_offsets = []
    offset = 0
    for frame_number, t, payload in ordered:
        decoded = payload.decode("utf-8", errors="replace")
        text_parts.append(decoded)
        segment_offsets.append(
            {"start": offset, "end": offset + len(decoded), "frame": frame_number, "time": t}
        )
        offset += len(decoded)

    return "".join(text_parts), segment_offsets


def _frame_for_offset(offset: int, segment_offsets: list[dict[str, Any]]) -> dict[str, Any]:
    for segment in segment_offsets:
        if segment["start"] <= offset < segment["end"]:
            return segment
    return segment_offsets[-1]


def _iter_json_messages(text: str):
    """Yield (message, start, end) for each JSON value in text, back to
    back or separated by whitespace -- works regardless of whether the
    wire framing is newline-delimited or has no delimiter at all, since
    JSON values are self-delimiting. Stops at the first non-JSON tail."""
    decoder = json.JSONDecoder()
    pos = 0
    while True:
        match = _NOT_WHITESPACE.search(text, pos)
        if not match:
            return
        start = match.start()
        try:
            message, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            return
        yield message, start, end
        pos = end


def _classify(message: Any) -> tuple[str, str | None, Any]:
    if not isinstance(message, dict):
        return "unknown", None, None

    method = message.get("method")
    has_id = "id" in message

    if method is not None:
        if not has_id:
            return "notification", method, None
        if method == "initialize":
            return "initialize", method, message.get("id")
        return "request", method, message.get("id")

    if has_id and ("result" in message or "error" in message):
        return "response", None, message.get("id")

    return "unknown", None, message.get("id")


def extract_exchange(file_path: str, stream_id: str) -> dict[str, Any]:
    """Reassemble a TCP conversation's payload, classify each JSON-RPC message
    (initialize / notification / request / response), pair requests with
    responses by `id`, and return the exchange as a timeline.

    Each direction's bytes are reassembled in TCP seq order (deduped, so
    retransmissions aren't double-counted) and parsed with a streaming JSON
    decoder that makes no assumption about newline- or Content-Length-based
    framing. Parsing a direction stops at the first byte sequence that isn't
    valid JSON; that's reported in `parse_warnings` rather than raised, so
    one malformed tail doesn't hide everything parsed before it.
    """
    endpoint_a, endpoint_b, frames = get_conversation_packets(file_path, stream_id)

    entries: list[dict[str, Any]] = []
    parse_warnings: list[dict[str, Any]] = []
    pending_requests: dict[Any, dict[str, Any]] = {}

    for endpoint in (endpoint_a, endpoint_b):
        sender_key = (endpoint["ip"], endpoint["port"])
        text, segment_offsets = _reassemble_direction(frames, sender_key)
        if not text:
            continue

        consumed_end = 0
        for message, start, end in _iter_json_messages(text):
            consumed_end = end
            segment = _frame_for_offset(start, segment_offsets)
            msg_type, method, msg_id = _classify(message)

            entry = {
                "frame": segment["frame"],
                "time": iso_timestamp(segment["time"]),
                "sender": endpoint,
                "type": msg_type,
                "method": method,
                "id": msg_id,
                "paired_frame": None,
            }

            if msg_type in ("request", "initialize") and msg_id is not None:
                pending_requests[msg_id] = entry
            elif msg_type == "response" and msg_id in pending_requests:
                request_entry = pending_requests.pop(msg_id)
                request_entry["paired_frame"] = entry["frame"]
                entry["paired_frame"] = request_entry["frame"]

            entries.append(entry)

        if consumed_end < len(text):
            trailing = text[consumed_end:].strip()
            if trailing:
                parse_warnings.append(
                    {
                        "sender": endpoint,
                        "unparsed_byte_count": len(trailing.encode("utf-8", errors="replace")),
                    }
                )

    entries.sort(key=lambda entry: entry["time"])

    return {
        "stream_id": stream_id,
        "endpoint_a": endpoint_a,
        "endpoint_b": endpoint_b,
        "message_count": len(entries),
        "timeline": entries,
        "parse_warnings": parse_warnings,
    }
