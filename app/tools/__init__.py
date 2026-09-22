"""Registered AI tools (spec §6). Importing registers them with the registry.

Every tool enforces its own input schema, is read-only or narrowly scoped,
and returns structured JSON — never raw shell output.
"""
from app.ai.registry import registry  # noqa: F401 (re-export for tool modules)
