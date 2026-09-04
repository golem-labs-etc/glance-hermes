"""Dashboard routes. Mounted at /api/plugins/glance-surfaces/.

`/health` and `/stats` are cache reads and never touch the scanned tree.
`/scan` is the one endpoint that starts work, it is a POST, and it returns
immediately: the scan runs on the runner's background thread.

The pane polls `/stats`. It must never poll `/scan` on a timer -- that would be
a full disk rescan every few seconds for every open window.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

try:
    from fastapi import APIRouter
except ImportError:  # pragma: no cover - fastapi ships with the dashboard
    APIRouter = None  # type: ignore

# The web server imports this file standalone, via
# ``importlib.util.spec_from_file_location`` with a synthetic module name and
# no parent package (see web_server._mount_plugin_api_routes). A relative
# import therefore raises "attempted relative import with no known parent
# package" and the routes never mount -- silently, because the loader logs and
# moves on. Resolve the adapter package by path instead.
try:  # normal package import, e.g. from the test suite
    from .. import runner  # type: ignore
    from ..categories import CATEGORIES  # type: ignore
except ImportError:  # loaded standalone by the dashboard
    import sys
    from pathlib import Path

    _adapter_dir = Path(__file__).resolve().parent.parent
    _parent = str(_adapter_dir.parent)
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    _pkg = __import__(_adapter_dir.name, fromlist=["runner", "categories"])
    runner = _pkg.runner
    CATEGORIES = _pkg.categories.CATEGORIES

log = logging.getLogger("glance.hermes.dashboard")

router = APIRouter() if APIRouter is not None else None


def health_payload() -> Dict[str, Any]:
    st = runner.stats()
    return {
        "ok": True,
        "scanner_available": st["scanner_available"],
        "policy": st["policy"] or runner.SCAN_POLICY,
        "has_cache": st["scanned_at"] is not None,
        "last_error": st["last_error"],
    }


def stats_payload() -> Dict[str, Any]:
    """Counts and digest, straight off the cache.

    `categories` is served from the single exported list so the pane can build
    its colour map from it rather than keeping a second copy that drifts.
    """
    st = runner.stats()
    st["categories"] = list(CATEGORIES)
    st["agent_severities"] = list(runner.AGENT_SEVERITIES)
    return st


def scan_payload() -> Dict[str, Any]:
    started = runner.kick_scan(force=True)
    return {"started": started, "scanning": runner.stats()["scanning"]}


if router is not None:

    @router.get("/health")
    async def health() -> Dict[str, Any]:
        return health_payload()

    @router.get("/stats")
    async def stats() -> Dict[str, Any]:
        return stats_payload()

    @router.post("/scan")
    async def scan() -> Dict[str, Any]:
        """Explicit, user-initiated. Returns at once; the work is backgrounded."""
        return scan_payload()
