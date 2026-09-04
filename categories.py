"""The category list, taken from the scanner rather than kept here.

There is deliberately no hardcoded list in this file, not even as a fallback.
A fallback list is a second copy, a second copy drifts, and the first symptom
of drift is a category the dashboard has no colour for -- which is the exact
failure this indirection exists to prevent.

If the scanner is not available the list is empty and the caller says so.
Empty and honest beats populated and stale.
"""

from __future__ import annotations

import json
import subprocess
import threading
from typing import List

from .runner import SCANNER_BIN, scanner_available

_lock = threading.Lock()
_cached: List[str] = []
_loaded = False


def _fetch() -> List[str]:
    if not scanner_available():
        return []
    try:
        proc = subprocess.run(
            [SCANNER_BIN, "surfaces", "--list-categories"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        doc = json.loads(proc.stdout)
        cats = doc.get("categories")
        return [str(c) for c in cats] if isinstance(cats, list) else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def get_categories(refresh: bool = False) -> List[str]:
    """Categories the engine can emit. Fetched once, then cached."""
    global _loaded, _cached
    with _lock:
        if _loaded and not refresh:
            return list(_cached)
    fetched = _fetch()
    with _lock:
        if fetched or refresh:
            _cached = fetched
            _loaded = True
        elif not _loaded:
            _cached = []
            _loaded = True
        return list(_cached)


class _CategoriesProxy:
    """Lazy sequence, so importing this module never shells out."""

    def __iter__(self):
        return iter(get_categories())

    def __len__(self) -> int:
        return len(get_categories())

    def __contains__(self, item) -> bool:
        return item in get_categories()

    def __repr__(self) -> str:
        return repr(get_categories())


CATEGORIES = _CategoriesProxy()
