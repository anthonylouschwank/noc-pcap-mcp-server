# noc-pcap-mcp-server

An MCP (Model Context Protocol) server that lets an LLM-based assistant
diagnose network problems from packet captures (PCAP/PCAPNG files), without
the operator needing to use Wireshark directly. Built for junior analysts in
a NOC (Network Operations Center) setting.

Built with the official [Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk)
(`FastMCP`) and [`scapy`](https://scapy.net/) for packet parsing.

## Tools

All tools take a `file_path` to a `.pcap`/`.pcapng` file. `stream_id` values
are returned by `list_tcp_conversations` and identify one TCP conversation.

| Tool | Parameters | Returns |
|---|---|---|
| `get_capture_summary` | `file_path: str` | Duration, packet count, protocol breakdown, top talkers |
| `list_tcp_conversations` | `file_path: str` | List of TCP conversations (4-tuple, `stream_id`, packet/byte counts, start/end time) |
| `analyze_tcp_conversation` | `file_path: str`, `stream_id: str` | RTT, retransmission count, zero-window events, duplicate ACKs, with the frame numbers that evidence each finding |
| `detect_security_anomalies` | `file_path: str` | Findings ranked by severity: port scans, ARP spoofing, high-entropy DNS queries, cleartext credentials |
| `extract_json_rpc_exchange` | `file_path: str`, `stream_id: str` | Reassembled JSON-RPC messages, classified (initialize / notification / request / response) and paired by `id`, as a timeline |

These are designed to be composable: a host LLM chains them (e.g. list
conversations, then analyze the relevant one) rather than calling one
do-everything tool.

## Requirements

- Python >= 3.11
- [uv](https://docs.astral.sh/uv/) (recommended) or `pip`

## Installation

```bash
git clone https://github.com/anthonylouschwank/noc-pcap-mcp-server.git
cd noc-pcap-mcp-server
uv sync
```

Or with `pip`:

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -e .
```

## Usage

### Standalone (for testing with an MCP-capable client, e.g. Claude Desktop)

Run over stdio:

```bash
uv run noc-pcap-mcp
```

Example Claude Desktop config entry:

```json
{
  "mcpServers": {
    "noc-pcap": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/noc-pcap-mcp-server", "noc-pcap-mcp"]
    }
  }
}
```

### As a dependency of another chatbot host

See [`noc-assistant`](https://github.com/anthonylouschwank/Proyecto1-RD),
which launches this server as a subprocess and aggregates its tools with
other MCP servers.

## Project layout

```
src/noc_pcap_mcp/
├── server.py         # tool registration (FastMCP)
├── pcap_utils.py      # capture summary + TCP conversation indexing
├── tcp_analysis.py    # RTT / retransmissions / zero-window per conversation
├── security.py        # port scans, ARP spoofing, DNS entropy, cleartext creds
└── jsonrpc.py          # TCP reassembly + JSON-RPC message classification
```

## Status

Scaffolding stage: tools are registered with their final signatures and
docstrings; the analysis logic in `pcap_utils.py`, `tcp_analysis.py`,
`security.py` and `jsonrpc.py` is not implemented yet.

## Author

Built by Anthony Schwank for CC3067 - Redes, Universidad del Valle de
Guatemala.
