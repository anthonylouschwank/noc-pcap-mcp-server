"""TCP payload reassembly and JSON-RPC message classification for one conversation."""

from typing import Any


def extract_exchange(file_path: str, stream_id: str) -> dict[str, Any]:
    """Reassemble a TCP conversation's payload, classify each JSON-RPC message
    (initialize / notification / request / response), pair requests with
    responses by `id`, and return the exchange as a timeline."""
    raise NotImplementedError(
        "TODO: reassemble TCP segments for stream_id in order, split on JSON "
        "message boundaries, classify by presence/absence of 'id' and 'method', "
        "match requests to responses by id, order by timestamp"
    )
