"""Normalize MCP Splunk query responses to a consistent format.

The ``mcp__splunk__run_splunk_query`` tool can return data in several
shapes depending on the query type, backend version, and error
conditions.  This module converts all variants into the canonical
``{"data": [<rows>], "count": <int>}`` dict that
``SplunkInvestigator.create_finding_from_result()`` expects.
"""

from typing import Any, Dict, List, Optional


def normalize_mcp_splunk_result(
    mcp_response: Any,
) -> Dict[str, Any]:
    """Normalize an MCP Splunk response to ``{"data": [...], "count": int}``.

    Handles the following input shapes:

    * ``dict`` with a ``"data"`` key (already canonical) --
      returned as-is with ``count`` filled in if missing.
    * ``dict`` with a ``"results"`` key -- ``results`` is renamed to
      ``data``.
    * Plain ``list`` -- wrapped in the canonical dict.
    * ``None`` -- returns empty result.
    * ``str`` -- treated as an error message; ``data`` is empty and the
      string is attached as ``"error"``.
    * Any other type -- treated as an error.

    Args:
        mcp_response: Raw return value from ``mcp__splunk__run_splunk_query``.

    Returns:
        Normalised dict ``{"data": [...], "count": int}`` with an
        optional ``"error"`` key when the response indicated failure.
    """
    if mcp_response is None:
        return {"data": [], "count": 0}

    if isinstance(mcp_response, str):
        return {"data": [], "count": 0, "error": mcp_response}

    if isinstance(mcp_response, list):
        return {"data": mcp_response, "count": len(mcp_response)}

    if isinstance(mcp_response, dict):
        # Already has "data" key -- canonical form
        if "data" in mcp_response:
            data = mcp_response["data"]
            if not isinstance(data, list):
                data = []
            result: Dict[str, Any] = {"data": data, "count": len(data)}
            # Preserve extra metadata
            for key in mcp_response:
                if key not in ("data", "count"):
                    result[key] = mcp_response[key]
            return result

        # Has "results" key (alternative MCP format)
        if "results" in mcp_response:
            data = mcp_response["results"]
            if not isinstance(data, list):
                data = []
            result = {"data": data, "count": len(data)}
            for key in mcp_response:
                if key not in ("results", "count"):
                    result[key] = mcp_response[key]
            return result

        # Dict without data/results -- wrap it as a single-row result
        return {"data": [mcp_response], "count": 1}

    # Fallback for unexpected types
    return {"data": [], "count": 0, "error": f"Unexpected type: {type(mcp_response).__name__}"}
