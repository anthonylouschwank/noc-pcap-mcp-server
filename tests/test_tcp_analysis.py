"""Tests for tcp_analysis: RTT, retransmissions, duplicate ACKs, zero window."""

import pytest

from noc_pcap_mcp.pcap_utils import list_conversations
from noc_pcap_mcp.tcp_analysis import analyze_conversation


def test_analyze_conversation_measures_handshake_rtt(sample_pcap):
    stream_id = list_conversations(sample_pcap)[0]["stream_id"]
    result = analyze_conversation(sample_pcap, stream_id)

    assert result["handshake"]["syn_frame"] == 4
    assert result["handshake"]["syn_ack_frame"] == 5
    assert result["handshake"]["rtt_seconds"] == pytest.approx(0.005, abs=1e-6)


def test_analyze_conversation_detects_retransmission(sample_pcap):
    stream_id = list_conversations(sample_pcap)[0]["stream_id"]
    result = analyze_conversation(sample_pcap, stream_id)

    assert result["summary"]["retransmission_count"] == 1
    retx = result["retransmissions"][0]
    assert retx["original_frame"] == 7
    assert retx["frame"] == 8
    assert retx["sender"]["ip"] == "10.0.0.1"


def test_analyze_conversation_unknown_stream_id_raises(sample_pcap):
    with pytest.raises(ValueError):
        analyze_conversation(sample_pcap, "999")


def test_analyze_conversation_detects_zero_window_and_recovery(zero_window_pcap):
    stream_id = list_conversations(zero_window_pcap)[0]["stream_id"]
    result = analyze_conversation(zero_window_pcap, stream_id)

    assert result["summary"]["zero_window_count"] == 1
    event = result["zero_window_events"][0]
    assert event["sender"]["ip"] == "10.0.1.2"
    assert event["recovered_frame"] is not None
    assert event["duration_seconds"] == pytest.approx(0.30, abs=1e-6)


def test_analyze_conversation_detects_duplicate_ack(duplicate_ack_pcap):
    stream_id = list_conversations(duplicate_ack_pcap)[0]["stream_id"]
    result = analyze_conversation(duplicate_ack_pcap, stream_id)

    assert result["summary"]["duplicate_ack_count"] == 1
    dup = result["duplicate_acks"][0]
    assert dup["sender"]["ip"] == "10.0.2.1"
    assert dup["ack"] == 501
