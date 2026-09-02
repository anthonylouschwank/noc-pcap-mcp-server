"""MCP server entry point: registers PCAP analysis tools over stdio."""

from mcp.server.mcpserver import MCPServer

from .jsonrpc import extract_exchange
from .pcap_utils import list_conversations, summarize_capture
from .security import detect_anomalies
from .tcp_analysis import analyze_conversation

mcp = MCPServer("noc-pcap-mcp")


@mcp.tool()
def get_capture_summary(file_path: str) -> dict:
    """Overview of a PCAP file: duration, packet count, protocols seen, top talkers."""
    return summarize_capture(file_path)


@mcp.tool()
def list_tcp_conversations(file_path: str) -> list[dict]:
    """Enumerate TCP conversations (4-tuple) in a PCAP with packet/byte counts and timing."""
    return list_conversations(file_path)


@mcp.tool()
def analyze_tcp_conversation(file_path: str, stream_id: str) -> dict:
    """RTT, retransmissions, zero-window events and duplicate ACKs for one TCP
    conversation, citing the frame numbers that evidence each finding."""
    return analyze_conversation(file_path, stream_id)


@mcp.tool()
def detect_security_anomalies(file_path: str) -> list[dict]:
    """Scan a PCAP for port scans, ARP spoofing, high-entropy DNS queries and
    cleartext credentials, ranked by severity."""
    return detect_anomalies(file_path)


@mcp.tool()
def extract_json_rpc_exchange(file_path: str, stream_id: str) -> dict:
    """Reassemble a TCP conversation's payload, classify JSON-RPC messages and
    pair requests with responses by id."""
    return extract_exchange(file_path, stream_id)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
