"""Glance surfaces adapter for Hermes.

Maps the Hermes layout onto the scanner's inventory schema, runs
`glance-scanner surfaces` off the hook path, and surfaces new critical and high
findings to the agent once per session.

It holds no detection logic. Every rule, threshold and severity lives in the
scanner's `src/surfaces/`. This adapter discovers paths, shells out, and
formats. If a pattern appears in this directory, it is in the wrong repository.

It does not block anything. Hermes can block, via `pre_tool_call`, but that is
the guard, the guard is not MIT, and it is not in this repo.
"""

from __future__ import annotations

import logging

from . import hooks

log = logging.getLogger("glance.hermes")

__all__ = ["register"]


def register(ctx) -> None:
    """Entry point. Hermes calls this once at plugin load.

    `post_tool_call` is deliberately not registered: the original design used it
    to rescan on `skill_view`, which is a read that fires constantly.
    """
    ctx.register_hook("on_session_start", hooks.on_session_start)
    ctx.register_hook("pre_llm_call", hooks.pre_llm_call)
    ctx.register_hook("on_skill_lifecycle", hooks.on_skill_lifecycle)
    ctx.register_hook("on_session_end", hooks.on_session_end)
