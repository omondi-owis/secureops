"""In-process SSE pub/sub for real-time dashboard updates.

Kept separate from main.py so routers/services can publish without creating
import cycles. Each subscriber is an asyncio.Queue drained by an SSE generator.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque

logger = logging.getLogger("secureops.stream")

_subscribers: set[asyncio.Queue] = set()
_recent: deque = deque(maxlen=200)


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


def publish(payload: dict) -> None:
    """Fan out a JSON-serializable event payload to all subscribers."""
    _recent.append(payload)
    dead = []
    for q in list(_subscribers):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass
        except Exception:  # pragma: no cover
            dead.append(q)
    for q in dead:
        _subscribers.discard(q)


def recent_events() -> list[dict]:
    return list(_recent)


def dumps(payload: dict) -> str:
    return json.dumps(payload, default=str)
