"""RTT, retransmission and zero-window analysis for a single TCP conversation."""

from typing import Any

from scapy.all import IP, IPv6, TCP

from .pcap_utils import get_conversation_packets, iso_timestamp


def _sender_of(packet: Any) -> dict[str, Any]:
    if IP in packet:
        ip = packet[IP].src
    elif IPv6 in packet:
        ip = packet[IPv6].src
    else:
        ip = None
    return {"ip": ip, "port": packet[TCP].sport}


def analyze_conversation(file_path: str, stream_id: str) -> dict[str, Any]:
    """RTT, retransmissions, zero-window events and duplicate ACKs for one
    TCP conversation, citing the frame numbers that evidence each finding."""
    endpoint_a, endpoint_b, frames = get_conversation_packets(file_path, stream_id)

    syn_frame: dict[str, Any] | None = None
    synack_frame: dict[str, Any] | None = None

    # seq numbers already sent, per sender, for payload-carrying segments
    seen_seqs: dict[tuple[str, int], dict[int, int]] = {}  # sender -> {seq: frame_number}
    retransmissions: list[dict[str, Any]] = []

    # ack numbers repeated back-to-back by the same sender on payload-less ACKs
    last_ack: dict[tuple[str, int], int] = {}
    duplicate_acks: list[dict[str, Any]] = []

    # zero-window conditions waiting to be closed by a later non-zero
    # window advertisement from the same sender
    open_zero_window: dict[tuple[str, int], dict[str, Any]] = {}
    zero_window_events: list[dict[str, Any]] = []

    for frame_number, packet in frames:
        tcp = packet[TCP]
        sender = _sender_of(packet)
        sender_key = (sender["ip"], sender["port"])
        payload_len = len(bytes(tcp.payload))
        t = float(packet.time)

        if tcp.flags.S and not tcp.flags.A and syn_frame is None:
            syn_frame = {"frame": frame_number, "time": t}
        elif tcp.flags.S and tcp.flags.A and synack_frame is None:
            synack_frame = {"frame": frame_number, "time": t}

        if payload_len > 0:
            sender_seqs = seen_seqs.setdefault(sender_key, {})
            if tcp.seq in sender_seqs:
                retransmissions.append(
                    {
                        "frame": frame_number,
                        "original_frame": sender_seqs[tcp.seq],
                        "sender": sender,
                        "seq": tcp.seq,
                        "time": iso_timestamp(t),
                    }
                )
            else:
                sender_seqs[tcp.seq] = frame_number
        elif not tcp.flags.S and not tcp.flags.F:
            # a pure ACK: flag it if it repeats the sender's previous ack number
            if last_ack.get(sender_key) == tcp.ack:
                duplicate_acks.append(
                    {
                        "frame": frame_number,
                        "sender": sender,
                        "ack": tcp.ack,
                        "time": iso_timestamp(t),
                    }
                )
            last_ack[sender_key] = tcp.ack

        if tcp.window == 0:
            open_zero_window.setdefault(
                sender_key, {"frame": frame_number, "sender": sender, "time": t}
            )
        elif sender_key in open_zero_window:
            opened = open_zero_window.pop(sender_key)
            zero_window_events.append(
                {
                    "frame": opened["frame"],
                    "sender": opened["sender"],
                    "time": iso_timestamp(opened["time"]),
                    "recovered_frame": frame_number,
                    "duration_seconds": round(t - opened["time"], 6),
                }
            )

    # zero-window conditions never recovered within the captured traffic
    for opened in open_zero_window.values():
        zero_window_events.append(
            {
                "frame": opened["frame"],
                "sender": opened["sender"],
                "time": iso_timestamp(opened["time"]),
                "recovered_frame": None,
                "duration_seconds": None,
            }
        )

    handshake_rtt_seconds = None
    if syn_frame and synack_frame:
        handshake_rtt_seconds = round(synack_frame["time"] - syn_frame["time"], 6)

    return {
        "stream_id": stream_id,
        "endpoint_a": endpoint_a,
        "endpoint_b": endpoint_b,
        "packet_count": len(frames),
        "handshake": {
            "syn_frame": syn_frame["frame"] if syn_frame else None,
            "syn_ack_frame": synack_frame["frame"] if synack_frame else None,
            "rtt_seconds": handshake_rtt_seconds,
        },
        "retransmissions": retransmissions,
        "duplicate_acks": duplicate_acks,
        "zero_window_events": zero_window_events,
        "summary": {
            "retransmission_count": len(retransmissions),
            "duplicate_ack_count": len(duplicate_acks),
            "zero_window_count": len(zero_window_events),
        },
    }
