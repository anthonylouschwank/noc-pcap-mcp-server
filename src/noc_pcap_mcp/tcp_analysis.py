"""RTT, retransmission and zero-window analysis for a single TCP conversation."""

from typing import Any


def analyze_conversation(file_path: str, stream_id: str) -> dict[str, Any]:
    """RTT, retransmissions, zero-window events and duplicate ACKs, with the
    specific frame numbers that evidence each finding."""
    raise NotImplementedError(
        "TODO: measure RTT from the SYN/SYN-ACK/ACK handshake, detect retransmissions "
        "via repeated seq numbers, detect zero-window via TCP window field, "
        "and reference the offending frame numbers"
    )
