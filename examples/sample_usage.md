# Example usage

These examples show the kind of natural-language request a host chatbot
(such as [`noc-assistant`](https://github.com/anthonylouschwank/Proyecto1-RD))
can resolve by chaining this server's tools.

## 1. Slow web application

> "The web app was slow during the incident captured in `slow-app.pcap`,
> what happened?"

Typical tool chain:

1. `list_tcp_conversations(file_path="slow-app.pcap")` -> find the
   conversation between the client and the web server.
2. `analyze_tcp_conversation(file_path="slow-app.pcap", stream_id="<id>")`
   -> RTT, retransmissions, zero-window events, with frame numbers.

## 2. Suspected malicious activity on a segment

> "Can you check `segment-review.pcap` for anything suspicious?"

Typical tool chain:

1. `detect_security_anomalies(file_path="segment-review.pcap")` -> ranked
   findings: port scans, ARP spoofing, high-entropy DNS queries, cleartext
   credentials.

## 3. JSON-RPC exchange between a client and server

> "What did the client and server exchange in `jsonrpc-session.pcap`?"

Typical tool chain:

1. `list_tcp_conversations(file_path="jsonrpc-session.pcap")` -> identify
   the relevant stream.
2. `extract_json_rpc_exchange(file_path="jsonrpc-session.pcap", stream_id="<id>")`
   -> classified messages (initialize / notification / request / response),
   paired by `id`, ordered as a timeline.
