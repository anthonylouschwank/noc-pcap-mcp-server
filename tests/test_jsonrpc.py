"""Tests for jsonrpc: TCP reassembly and JSON-RPC message classification."""

import pytest

from noc_pcap_mcp.jsonrpc import extract_exchange
from noc_pcap_mcp.pcap_utils import list_conversations


def test_extract_exchange_classifies_each_message_type(jsonrpc_pcap):
    stream_id = list_conversations(jsonrpc_pcap)[0]["stream_id"]
    result = extract_exchange(jsonrpc_pcap, stream_id)

    assert result["message_count"] == 5
    types = [entry["type"] for entry in result["timeline"]]
    assert types == ["initialize", "response", "notification", "request", "response"]


def test_extract_exchange_timeline_is_chronological(jsonrpc_pcap):
    stream_id = list_conversations(jsonrpc_pcap)[0]["stream_id"]
    result = extract_exchange(jsonrpc_pcap, stream_id)

    times = [entry["time"] for entry in result["timeline"]]
    assert times == sorted(times)


def test_extract_exchange_pairs_requests_with_responses_by_id(jsonrpc_pcap):
    stream_id = list_conversations(jsonrpc_pcap)[0]["stream_id"]
    result = extract_exchange(jsonrpc_pcap, stream_id)

    by_type_and_id = {(e["type"], e["id"]): e for e in result["timeline"]}

    init_request = by_type_and_id[("initialize", 1)]
    init_response = by_type_and_id[("response", 1)]
    assert init_request["paired_frame"] == init_response["frame"]
    assert init_response["paired_frame"] == init_request["frame"]

    tool_request = by_type_and_id[("request", 2)]
    tool_response = by_type_and_id[("response", 2)]
    assert tool_request["method"] == "tools/call"
    assert tool_request["paired_frame"] == tool_response["frame"]


def test_extract_exchange_notification_has_no_id(jsonrpc_pcap):
    stream_id = list_conversations(jsonrpc_pcap)[0]["stream_id"]
    result = extract_exchange(jsonrpc_pcap, stream_id)

    notifications = [e for e in result["timeline"] if e["type"] == "notification"]
    assert len(notifications) == 1
    assert notifications[0]["method"] == "notifications/initialized"
    assert notifications[0]["id"] is None


def test_extract_exchange_unknown_stream_id_raises(jsonrpc_pcap):
    with pytest.raises(ValueError):
        extract_exchange(jsonrpc_pcap, "999")


def test_extract_exchange_reports_malformed_tail_without_losing_valid_messages(
    jsonrpc_malformed_tail_pcap,
):
    stream_id = list_conversations(jsonrpc_malformed_tail_pcap)[0]["stream_id"]
    result = extract_exchange(jsonrpc_malformed_tail_pcap, stream_id)

    assert result["message_count"] == 1
    assert result["timeline"][0]["method"] == "ping"
    assert len(result["parse_warnings"]) == 1
    assert result["parse_warnings"][0]["unparsed_byte_count"] > 0
