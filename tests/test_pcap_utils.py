"""Tests for pcap_utils: capture summaries and TCP conversation listing."""

import pytest

from noc_pcap_mcp.pcap_utils import list_conversations, summarize_capture


def test_summarize_capture_counts_packets_and_protocols(sample_pcap):
    summary = summarize_capture(sample_pcap)

    assert summary["packet_count"] == 9
    assert summary["protocol_counts"] == {"ARP": 2, "DNS": 1, "TCP": 6}
    assert summary["duration_seconds"] == pytest.approx(0.28, abs=1e-6)


def test_summarize_capture_ranks_top_talkers_by_bytes(sample_pcap):
    summary = summarize_capture(sample_pcap)
    talkers_by_ip = {talker["ip"]: talker for talker in summary["top_talkers"]}

    assert talkers_by_ip["10.0.0.1"]["packets"] == 6
    assert talkers_by_ip["10.0.0.2"]["packets"] == 3
    assert summary["top_talkers"][0]["ip"] == "10.0.0.1"


def test_summarize_capture_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        summarize_capture("does-not-exist.pcap")


def test_summarize_capture_empty_file_raises(empty_pcap):
    with pytest.raises(ValueError):
        summarize_capture(empty_pcap)


def test_list_conversations_groups_bidirectional_traffic_into_one_stream(sample_pcap):
    conversations = list_conversations(sample_pcap)

    assert len(conversations) == 1
    conv = conversations[0]
    assert conv["stream_id"] == "0"
    assert conv["packet_count"] == 6  # SYN, SYN-ACK, ACK, data, retransmission, response

    endpoints = {
        (conv["endpoint_a"]["ip"], conv["endpoint_a"]["port"]),
        (conv["endpoint_b"]["ip"], conv["endpoint_b"]["port"]),
    }
    assert endpoints == {("10.0.0.1", 5000), ("10.0.0.2", 80)}


def test_list_conversations_ignores_non_tcp_packets(sample_pcap):
    conversations = list_conversations(sample_pcap)
    total_tcp_packets = sum(conv["packet_count"] for conv in conversations)

    assert total_tcp_packets == 6  # the 2 ARP + 1 DNS packets are excluded


def test_list_conversations_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        list_conversations("does-not-exist.pcap")
