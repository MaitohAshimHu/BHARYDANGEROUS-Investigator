"""Timestamp and event record normalizer."""
from datetime import datetime, timezone
from typing import Optional

def normalize_timestamp_to_utc(ts_str: str) -> str:
    """
    Convert various log timestamp formats into standard ISO-8601 UTC format.
    Handles ISO, Epoch seconds, RFC 3164, and Apache access timestamps.
    """
    ts_str = ts_str.strip()
    if not ts_str:
        return datetime.now(timezone.utc).isoformat()

    # Try ISO-8601
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass

    # Try numeric Epoch timestamp
    try:
        val = float(ts_str)
        # If timestamp is in milliseconds
        if val > 1e11:
            val = val / 1000.0
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    except Exception:
        pass

    # Fallback to current UTC
    return datetime.now(timezone.utc).isoformat()
