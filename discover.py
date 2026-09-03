"""Hermes layout -> the scanner's inventory schema.

This module knows where Hermes keeps things. It knows nothing about what is
wrong with them: every rule, threshold and severity lives in the scanner's
`src/surfaces/`, which is public and MIT. If you find yourself adding a pattern
here, it belongs there instead.

Paths are realpath'd on both sides of every comparison. On macOS `/var` is a
symlink to `/private/var`, so comparing a resolved path against an unresolved
one silently produced `../../..` and disabled four detections last time, with
the suite passing the whole way. Resolve both, always.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - yaml ships with Hermes
    yaml = None


SKILL_FILENAME = "SKILL.md"
PLUGIN_MANIFEST = "plugin.yaml"
PROFILE_CONFIG = "config.yaml"

# Directories that are never worth walking into.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".cache", "audio_cache", ".glance",
}

MAX_DEPTH = 6


def hermes_home(env: Optional[Dict[str, str]] = None) -> Path:
    """The Hermes root, resolved.

    `HERMES_HOME` wins; `~/.hermes` is the default.
    """
    e = os.environ if env is None else env
    raw = e.get("HERMES_HOME") or str(Path.home() / ".hermes")
    return real(Path(raw))


def real(p: Path) -> Path:
    """Resolve symlinks and `..`, without requiring the path to exist.

    Both sides of every path comparison in this adapter go through here.
    """
    try:
        return Path(os.path.realpath(str(p)))
    except OSError:
        return Path(os.path.abspath(str(p)))


def within(child: Path, parent: Path) -> bool:
    """True when `child` is inside `parent`, both resolved first."""
    c, p = real(child), real(parent)
    try:
        c.relative_to(p)
        return True
    except ValueError:
        return False


def _walk(root: Path, max_depth: int = MAX_DEPTH) -> Iterable[Path]:
    """Bounded, symlink-refusing walk. A runaway recursion is a hang."""
    root = real(root)
    if not root.is_dir():
        return
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                p = Path(e.path)
                if e.is_dir():
                    if e.name in SKIP_DIRS:
                        continue
                    stack.append((p, depth + 1))
                elif e.is_file():
                    yield p
            except OSError:
                continue


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    if yaml is None:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = yaml.safe_load(fh)
        return doc if isinstance(doc, dict) else None
    except Exception:
        # A malformed config is not a finding and must not stop the walk.
        return None


def _mcp_entries(source: Path, doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map one config's `mcp_servers` block onto inventory entries.

    Both the dict form (`{name: {...}}`) and the list form are accepted, which
    is what the profiles on a real machine actually contain.
    """
    block = doc.get("mcp_servers") or doc.get("mcpServers") or {}
    pairs: List[Any] = []
    if isinstance(block, dict):
        pairs = list(block.items())
    elif isinstance(block, list):
        pairs = [(v.get("name", "(unnamed)"), v) for v in block if isinstance(v, dict)]

    out: List[Dict[str, Any]] = []
    for name, v in pairs:
        if not isinstance(v, dict):
            continue
        env = v.get("env") if isinstance(v.get("env"), dict) else {}
        env_str = {str(k): str(x) for k, x in env.items()}
        out.append(
            {
                "source": str(source),
                "name": str(name),
                "transport": v.get("transport") or v.get("type")
                or ("http" if v.get("url") else "stdio"),
                "command": v.get("command"),
                "args": [str(a) for a in v.get("args", []) or []],
                "url": v.get("url"),
                "env_keys": sorted(env_str.keys()),
                "env_values_hashed": [_sha256(env_str[k]) for k in sorted(env_str)],
                # Inline values, so `secret_in_config` can judge the value shape.
                # The inventory file carrying these is written 0600 and unlinked
                # by the runner; it never persists.
                "env": env_str,
            }
        )
    return out


def build_inventory(home: Optional[Path] = None) -> Dict[str, Any]:
    """Walk a Hermes tree and emit the scanner's inventory schema.

    Prompt surfaces are `SKILL.md` and `plugin.yaml`. A plugin manifest is
    included because its description reaches the model as text, so it is a
    prompt surface in the same sense a skill is.
    """
    root = real(home) if home is not None else hermes_home()

    mcp_servers: List[Dict[str, Any]] = []
    prompt_files: List[Dict[str, str]] = []
    seen_prompts = set()

    # MCP servers: profiles/*/config.yaml
    profiles_dir = root / "profiles"
    if profiles_dir.is_dir():
        try:
            profile_dirs = sorted(p for p in profiles_dir.iterdir() if p.is_dir())
        except OSError:
            profile_dirs = []
        for prof in profile_dirs:
            cfg = prof / PROFILE_CONFIG
            if cfg.is_file():
                doc = _load_yaml(cfg)
                if doc:
                    mcp_servers.extend(_mcp_entries(real(cfg), doc))

    # Prompt surfaces: skills/, profiles/*/skills/, plugins/*/
    search_roots = [root / "skills", root / "plugins"]
    if profiles_dir.is_dir():
        try:
            search_roots.extend(
                p / "skills" for p in profiles_dir.iterdir() if p.is_dir()
            )
        except OSError:
            pass

    for sr in search_roots:
        for f in _walk(sr):
            if f.name not in (SKILL_FILENAME, PLUGIN_MANIFEST):
                continue
            rp = real(f)
            key = str(rp)
            if key in seen_prompts:
                continue
            seen_prompts.add(key)
            prompt_files.append({"path": key})
            # A plugin manifest may also declare MCP servers of its own.
            if f.name == PLUGIN_MANIFEST:
                doc = _load_yaml(f)
                if doc:
                    mcp_servers.extend(_mcp_entries(rp, doc))

    prompt_files.sort(key=lambda d: d["path"])
    mcp_servers.sort(key=lambda d: (d["source"], d["name"]))

    return {
        "schema": 1,
        "mcp_servers": mcp_servers,
        "prompt_files": prompt_files,
        # Hermes plugin source is scanned by the code engine on request, not on
        # every session start: it is slow and it is not an agent surface.
        "code_files": [],
    }


def inventory_digest(inv: Dict[str, Any]) -> str:
    """Digest over (path, mtime, size) for every file in the inventory.

    Not a time-based TTL. Nothing changes between turns unless a file changes,
    so a 60-second TTL just rescans the disk on a timer for no reason. This
    changes exactly when the scanned bytes change.
    """
    h = hashlib.sha256()
    paths = [d["path"] for d in inv.get("prompt_files", [])]
    paths += [d["source"] for d in inv.get("mcp_servers", [])]
    paths += [d["path"] for d in inv.get("code_files", [])]
    for p in sorted(set(paths)):
        try:
            st = os.stat(p)
            h.update(f"{p}\0{int(st.st_mtime_ns)}\0{st.st_size}\n".encode("utf-8"))
        except OSError:
            h.update(f"{p}\0missing\n".encode("utf-8"))
    return h.hexdigest()
