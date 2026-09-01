"""The only thing in this adapter that scans.

No hook ever scans. Hooks read what this has already written. That separation
is the whole performance and safety story: `pre_llm_call` runs on every turn of
every session, and anything it does is paid for on the agent's critical path.

State lives under `$HERMES_HOME/.glance/`:

    cache.json      the last completed scan, plus the digest it was taken at
    baseline.json   findings present the first time we ever looked
    scan.lock       so two sessions do not scan the same tree at once

Invalidation is by a digest of (path, mtime, size) across the inventory, not by
a time-to-live. Nothing changes between turns unless a file changes.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .discover import build_inventory, hermes_home, inventory_digest, real

# Part B passes strict. An agent consuming raw markdown never sees a code
# fence, so a directive quoted in one reaches it exactly like any other text.
SCAN_POLICY = "strict"

# Severities the agent is ever told about. `fenced_directive` is medium and so
# is correctly never in this set; `unpinned_remote_exec` is info and likewise.
AGENT_SEVERITIES = ("critical", "high")

SCANNER_BIN = os.environ.get("GLANCE_SCANNER_BIN", "glance-scanner")

# The oldest engine whose output this adapter is willing to present without
# saying something. Below this the scanner is not merely missing features: on a
# stock machine 1.3.1 returns 1602 critical findings under this policy where
# 1.4.0 returns 0, and every one of the 1602 is wrong. A README line cannot
# reach a user with an old global install. This can.
MIN_ENGINE = "1.4.0"

# Above this many critical findings on a FIRST run, the notice says the number
# is implausible and the pane must be checked before the tool is trusted. The
# baseline is still written -- a security tool that is red on install teaches
# people to ignore it, and refusing to baseline would do that.
#
# 25, and the evidence for it. Findings are deduplicated by content, so one
# planted file is one finding no matter how many profiles carry it, and this
# number does not grow with the size of the tree:
#
#   a real stock machine, 1904 prompt files, good engine     0 critical
#   the same machine, 1.3.1                               1602 critical
#   this adapter installed from the mirror                   0 critical
#   the suite's clean tree                                   0 critical
#   the suite's deliberately hostile tree, 5 files            5 critical
#
# The worst tree we construct on purpose reaches 5. Nothing legitimate has ever
# reached double figures. A broken engine reached 1602. 25 is five times the
# constructed worst case and one sixty-fourth of the observed failure, so it
# sits in an empty band -- high enough that a genuine compromise, which plants
# a handful of distinct files, is reported as a compromise rather than as a
# malfunction, and low enough that any engine defect of the 1.3.1 class trips
# it immediately.
IMPLAUSIBLE_CRITICAL = 25

_LOCK_STALE_SECONDS = 300
_SCAN_TIMEOUT_SECONDS = 180

# How much of a diagnosis we keep. Long enough for a stack-ish stderr line,
# short enough that it stays readable in a dashboard pane.
_ERR_MAX = 500
_STDOUT_SNIPPET = 160


class _State:
    """One global object. The scanned filesystem is not per-session.

    A per-session copy of this would mean one session's tool call rewriting
    another session's view of the same disk.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.cache: Optional[Dict[str, Any]] = None
        self.scanning = False
        self.dirty = False
        self.last_error: Optional[str] = None


_state = _State()


def glance_dir(home: Optional[Path] = None) -> Path:
    return (real(home) if home is not None else hermes_home()) / ".glance"


def _cache_path(home: Optional[Path] = None) -> Path:
    return glance_dir(home) / "cache.json"


def _baseline_path(home: Optional[Path] = None) -> Path:
    return glance_dir(home) / "baseline.json"


def _lock_path(home: Optional[Path] = None) -> Path:
    return glance_dir(home) / "scan.lock"


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def _write_json_atomic(path: Path, doc: Dict[str, Any]) -> None:
    """Write via a temp file and rename, so a reader never sees a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def get_cached(home: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """The last completed scan. Never scans, never stats the scanned tree.

    Reads the cache file once, then serves an in-memory copy that the scan
    thread keeps current. This is what `pre_llm_call` calls, so it has to be
    memory-speed.
    """
    with _state.lock:
        if _state.cache is not None:
            return _state.cache
    doc = _read_json(_cache_path(home))
    with _state.lock:
        if _state.cache is None:
            _state.cache = doc
        return _state.cache


def get_baseline(home: Optional[Path] = None) -> Dict[str, Any]:
    return _read_json(_baseline_path(home)) or {}


def baseline_ids(home: Optional[Path] = None) -> set:
    return set(get_baseline(home).get("ids") or [])


def has_baseline(home: Optional[Path] = None) -> bool:
    """True once a TRUSTWORTHY scan has recorded a baseline.

    Two things are deliberately not the test.

    The presence of the file is not enough: the scanner-missing notice writes
    its one-shot mark into this same document before any scan has ever run, and
    a file-existence test would make the first successful scan look like a
    second run -- nothing would be baselined and the first-run notice would
    never fire. The `ids` key is written only by a completed scan.

    And a completed scan is not enough either. A baseline is a claim about what
    was already present, and an engine we refuse to report findings from cannot
    be trusted to make that claim. 1.3.1 returned 1602 critical findings on a
    stock machine where 1.4.0 returns none; a baseline built from that is 1602
    assertions that garbage is normal. So the engine that wrote it is recorded
    and checked here, and a baseline written below the floor counts as absent.

    A MISSING `engine_version` also counts as absent. Every baseline written
    before this field existed was written by an engine at or below 1.3.1 or by
    1.4.0 in the hours before this shipped, and nothing on disk distinguishes
    them. That forces exactly one re-baseline per installation, announced by
    the ordinary first-run notice with the sanity gate on it. Taken
    deliberately: it is free now and it stops being free later.
    """
    doc = _read_json(_baseline_path(home))
    if not isinstance(doc, dict) or "ids" not in doc:
        return False
    return not engine_below_floor(doc.get("engine_version"))


def take_first_run_notice(home: Optional[Path] = None) -> Optional[Dict[str, int]]:
    """Claim the one-time first-run notice, or return None.

    Returns its payload exactly once per machine and clears the flag on disk
    before returning, so a crash between the claim and the announcement loses
    the notice rather than repeating it. Losing it is the better failure: the
    findings are still in the pane, whereas an agent told the same thing every
    session learns to skip the message.

    Persisted rather than held in memory because "once" has to survive a
    restart, which is the fourth test.
    """
    path = _baseline_path(home)
    doc = _read_json(path)
    if not doc or not doc.get("notice_pending"):
        return None
    payload = {
        "total": int(doc.get("notice_total") or 0),
        "critical": int(doc.get("notice_critical") or 0),
        "implausible": bool(doc.get("notice_implausible")),
    }
    doc["notice_pending"] = False
    try:
        _write_json_atomic(path, doc)
    except Exception:
        # Could not clear the flag. Say nothing rather than risk saying it on
        # every turn: an unclearable flag would otherwise repeat forever.
        return None
    return payload


def _arm_once(home: Optional[Path], prefix: str, detail: str) -> None:
    """Arm a one-time notice under `prefix`. Idempotent.

    Written into the baseline document rather than a file of its own, beside
    `notice_pending`, so there is exactly one piece of state to reason about.
    `<prefix>_armed` is set on the first arming and never cleared, so a machine
    that stays in the same condition arms once, not once per session.
    """
    path = _baseline_path(home)
    doc = _read_json(path) or {}
    if doc.get(prefix + "_armed"):
        return
    doc[prefix + "_armed"] = True
    doc[prefix + "_pending"] = True
    doc[prefix + "_error"] = detail[:_ERR_MAX]
    try:
        _write_json_atomic(path, doc)
    except Exception:
        # Nothing to do. The pane still carries the same facts, and the next
        # scan attempt will try to arm again.
        pass


def _take_once(home: Optional[Path], prefix: str) -> Optional[str]:
    """Claim a one-time notice, or return None.

    Same one-shot discipline as `take_first_run_notice`: the flag is cleared on
    disk BEFORE the payload is returned, so a crash between the claim and the
    announcement loses the notice rather than repeating it every turn.
    """
    path = _baseline_path(home)
    doc = _read_json(path)
    if not doc or not doc.get(prefix + "_pending"):
        return None
    detail = str(doc.get(prefix + "_error") or "")
    doc[prefix + "_pending"] = False
    try:
        _write_json_atomic(path, doc)
    except Exception:
        return None
    return detail or None


def _mark_scanner_missing(home: Optional[Path], detail: str) -> None:
    _arm_once(home, "scanner_missing", detail)


def take_scanner_missing_notice(home: Optional[Path] = None) -> Optional[str]:
    """The one-time notice that nothing is being scanned.

    Returns the stored `last_error` text -- the message that already names the
    binary and says how to fix it -- so the agent feed and the pane say the
    same thing.
    """
    return _take_once(home, "scanner_missing")


def _version_tuple(v: str) -> tuple:
    """Leading dotted integers of a version string, for ordering only.

    Deliberately not a semver parser. It answers one question -- is this engine
    older than the floor -- and anything it cannot read sorts as (), which is
    below every real version and therefore arms the notice. Failing toward
    "say something" is right here: an unreadable version is not a reassurance.
    """
    out = []
    for part in str(v or "").split("."):
        digits = ""
        for ch in part:
            if not ch.isdigit():
                break
            digits += ch
        if not digits:
            break
        out.append(int(digits))
    return tuple(out)


def engine_below_floor(version: Optional[str]) -> bool:
    return _version_tuple(version) < _version_tuple(MIN_ENGINE)


def engine_stale(home: Optional[Path] = None) -> bool:
    """Did the last completed scan come from an engine below the floor?

    Derived from the cache on every call rather than latched on disk, because
    this now gates the whole agent feed: the moment someone upgrades the
    scanner and a scan completes, the gate has to open by itself. A latched
    flag would need clearing, and a flag that needs clearing is a flag that
    stays set.

    An absent cache is NOT stale -- a fresh install before its first scan has
    no engine version and must not be treated as a bad one. An engine that
    reports no version at all is also not treated as stale HERE, deliberately:
    the once-only warning still fires on it, but suppressing every finding on a
    machine because a version string was missing is a bigger hammer than the
    evidence justifies.
    """
    cache = get_cached(home)
    if not cache:
        return False
    version = cache.get("engine_version")
    if not version:
        return False
    return engine_below_floor(version)


def engine_floor_detail(home: Optional[Path] = None) -> str:
    """The sentence naming the installed version and the required one."""
    cache = get_cached(home) or {}
    return (
        f"{SCANNER_BIN} reports version {cache.get('engine_version') or 'unknown'}; "
        f"this adapter expects {MIN_ENGINE} or newer. Upgrade with "
        f"`npm install -g glance-scanner@latest`."
    )


# Fields the pane is allowed to see. A whitelist, not a blacklist: the scanner
# omits matched text by default, and this makes the dashboard's guarantee
# independent of that default holding.
_PANE_FIELDS = ("id", "severity", "category", "path", "line", "end_line", "surface")


def _for_pane(f: Dict[str, Any]) -> Dict[str, Any]:
    return {k: f[k] for k in _PANE_FIELDS if k in f}


def findings_by_baseline(home: Optional[Path] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Split the cached findings into new and baselined, for the pane.

    Every severity, unlike `new_findings`, which is the agent path and stops at
    critical and high. Entering the baseline suppresses a finding from the
    agent feed; it does not remove it from the machine, and the person looking
    at the pane is entitled to the whole list.
    """
    cache = get_cached(home) or {}
    base = baseline_ids(home)
    new: List[Dict[str, Any]] = []
    old: List[Dict[str, Any]] = []
    order = {s: i for i, s in enumerate(("critical", "high", "medium", "info"))}
    for f in cache.get("findings", []):
        (old if f.get("id") in base else new).append(_for_pane(f))
    for bucket in (new, old):
        bucket.sort(key=lambda f: (order.get(f.get("severity"), 9), f.get("path", ""), f.get("line") or 0))
    return {"new": new, "baselined": old}


def _tally(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for f in findings:
        sev = f.get("severity")
        if sev in out:
            out[sev] += 1
    return out


# --------------------------------------------------------- error reporting
#
# There are four distinct ways a scan run fails and they need four distinct
# things done about them. Collapsing them into one message costs debugging
# time: it names one cause, and the reader spends their afternoon on it.
#
#   not on PATH        install it, or set GLANCE_SCANNER_BIN
#   spawn failure      it is there but the OS would not run it -- errno says why
#   non-zero exit      it ran and objected -- its own stderr says why
#   unparseable stdout it ran, exited 0, and printed something that is not JSON
#
# The last one is the only genuine "the parser is the problem" case, and it
# should be rare. It was previously the label on all four.

def _set_error(msg: Optional[str]) -> None:
    """Store the diagnosis under the lock that `stats` reads it under."""
    with _state.lock:
        _state.last_error = msg[:_ERR_MAX] if msg else msg


def _first_line(s: Optional[str]) -> str:
    for line in (s or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _spawn_error(exc: OSError) -> str:
    """The process never started. The errno is the entire diagnosis.

    Reached when the file passes `shutil.which` but `execve` refuses it: a
    missing interpreter in the shebang, a permission bit dropped by a package
    manager, a text file where a binary is expected. Nothing was run, so there
    is no stdout to blame.
    """
    code = errno.errorcode.get(exc.errno, "?") if exc.errno is not None else "?"
    target = getattr(exc, "filename", None) or SCANNER_BIN
    hint = {
        errno.ENOENT: "The file or its interpreter is missing; check its shebang.",
        errno.EACCES: "It is not executable; chmod +x it.",
        errno.ENOEXEC: "The OS would not execute it; check its shebang.",
        errno.EISDIR: "That path is a directory.",
    }.get(exc.errno, "")
    msg = (
        f"cannot start {SCANNER_BIN}: [errno {exc.errno} {code}] "
        f"{exc.strerror or exc} ({target})"
    )
    return msg + (f". {hint}" if hint else "")


def _output_error(proc: "subprocess.CompletedProcess") -> str:
    """stdout would not parse. Say which of the two reasons that was.

    Called only after the parse has already failed, so a findings run -- which
    exits 1 with perfectly good JSON -- never reaches here. The exit code is
    consulted after the parse, never before, or a run that found something
    would be reported as an error.
    """
    err = _first_line(proc.stderr)
    if proc.returncode != 0:
        # The common case by far. The scanner ran, rejected its input or hit an
        # error, and said so. Its own words are more useful than ours.
        return (
            f"{SCANNER_BIN} exited {proc.returncode}: "
            + (err or "no output on stderr")
        )
    out = (proc.stdout or "").strip()
    if not out:
        return (
            f"{SCANNER_BIN} exited 0 but wrote nothing to stdout"
            + (f" (stderr: {err})" if err else "")
        )
    return (
        f"{SCANNER_BIN} exited 0 and wrote output that is not JSON: {out[:_STDOUT_SNIPPET]!r}"
    )


# ---------------------------------------------------------------- locking

def _acquire_lock(home: Optional[Path] = None) -> bool:
    """Exclusive create. Returns False when another session holds it.

    A lock older than `_LOCK_STALE_SECONDS` is treated as abandoned, because a
    killed process leaves the file behind and the alternative is a tree that
    never scans again.
    """
    p = _lock_path(home)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"pid": os.getpid(), "at": time.time()}))
        return True
    except FileExistsError:
        try:
            age = time.time() - p.stat().st_mtime
        except OSError:
            return False
        if age > _LOCK_STALE_SECONDS:
            try:
                p.unlink()
            except OSError:
                return False
            return _acquire_lock(home)
        return False
    except OSError:
        return False


def _release_lock(home: Optional[Path] = None) -> None:
    try:
        _lock_path(home).unlink()
    except OSError:
        pass


# ---------------------------------------------------------------- scanning

def scanner_available() -> bool:
    return shutil.which(SCANNER_BIN) is not None


def run_scan(home: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Discover, shell out to the scanner, write the cache. Blocking.

    Called only from the background thread and from tests. A hook must never
    reach this function.
    """
    root = real(home) if home is not None else hermes_home()
    inv = build_inventory(root)
    digest = inventory_digest(inv)

    if not scanner_available():
        detail = (
            f"{SCANNER_BIN} not found on PATH. Install glance-scanner, or set "
            "GLANCE_SCANNER_BIN to its full path."
        )
        _set_error(detail)
        # Silence here is indistinguishable from a clean machine. Arm the
        # one-time notice so the agent feed says so once, instead of leaving
        # the fact to a pane a new user may never open.
        _mark_scanner_missing(root, detail)
        return None

    fd, tmp = tempfile.mkstemp(prefix="glance-inv-", suffix=".json")
    try:
        # 0600: the inventory carries inline env values so the scanner can judge
        # their shape. It is unlinked below and never persists.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(inv, fh)

        argv = [SCANNER_BIN, "surfaces", "--inventory", tmp, "--json",
                "--policy", SCAN_POLICY]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=_SCAN_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            # Never started. Distinct from anything the scanner could report,
            # because the scanner did not run.
            _set_error(_spawn_error(exc))
            return None
        except subprocess.TimeoutExpired:
            _set_error(
                f"{SCANNER_BIN} did not finish within {_SCAN_TIMEOUT_SECONDS}s "
                "and was killed. No result was read."
            )
            return None
        except subprocess.SubprocessError as exc:
            _set_error(f"cannot run {SCANNER_BIN}: {type(exc).__name__}: {exc}")
            return None

        # The CLI exits 1 when it found something critical or high. That is a
        # result, not a failure, so success is defined by the parse and the
        # exit code is only consulted once the parse has already failed.
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            _set_error(_output_error(proc))
            return None
    except OSError as exc:
        # Writing the inventory temp file failed. Also not the scanner.
        _set_error(f"cannot write the inventory file: {exc}")
        return None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    cache = {
        "digest": digest,
        "scanned_at": report.get("scanned_at"),
        "policy": report.get("policy"),
        "engine_version": report.get("engine_version"),
        "counts": report.get("counts", {}),
        "warnings": report.get("warnings", []),
        "findings": report.get("findings", []),
        "total_scanned": report.get("total_scanned", 0),
    }
    _write_json_atomic(_cache_path(root), cache)

    # First look ever: record what was already here and alert on none of it.
    # A tool that is red on install teaches people to ignore it.
    if not has_baseline(root):
        ids = sorted({f["id"] for f in cache["findings"] if "id" in f})
        critical = sum(1 for f in cache["findings"] if f.get("severity") == "critical")
        # What the baseline actually SUPPRESSED: findings the agent would
        # otherwise have been told about. `info` and `medium` never reach the
        # agent feed at all, so baselining them hides nothing and is not worth
        # a notice -- an ordinary install has a couple of `npx -y` info
        # findings, and a notice on those trains the reader to skip it.
        suppressed = sum(1 for f in cache["findings"] if f.get("severity") in AGENT_SEVERITIES)
        # MERGE, do not replace. `_arm_once` may already have written a
        # one-shot flag into this document -- the engine floor is armed a few
        # lines above, on the same scan -- and a wholesale write silently
        # erased it. Caught by V18a, which saw no notice at all.
        doc = _read_json(_baseline_path(root)) or {}
        doc.update(
            {
                "created_at": cache["scanned_at"],
                # Which engine's judgement this baseline encodes. Read back by
                # has_baseline: a baseline is only as trustworthy as the thing
                # that decided what "already present" means.
                "engine_version": cache.get("engine_version"),
                "digest": digest,
                "ids": ids,
                # The agent is told ONCE that this happened. Without it, a user
                # installing onto an already-compromised machine has that
                # finding filed into the baseline before they ever see it, and
                # nothing mentions it again: the security tool would create a
                # permanent blind spot at install time, silently.
                #
                # Pending only when the baseline actually took something out of
                # the agent feed. A clean tree says nothing.
                "notice_pending": suppressed > 0,
                "notice_total": len(ids),
                "notice_critical": critical,
                # The engine floor only catches engines already known to be
                # bad. This catches the rest: any count this large is far more
                # likely to be a broken scanner than a machine in that much
                # trouble, and either way it is not something to file silently
                # into a baseline. The baseline is still written -- refusing to
                # would make the tool red on install, which is the behaviour
                # that teaches people to ignore it.
                "notice_implausible": critical > IMPLAUSIBLE_CRITICAL,
            }
        )
        _write_json_atomic(_baseline_path(root), doc)

    with _state.lock:
        _state.cache = cache
        _state.last_error = None
    return cache


def _scan_worker(home: Optional[Path]) -> None:
    root = real(home) if home is not None else hermes_home()
    if not _acquire_lock(root):
        with _state.lock:
            _state.scanning = False
        return
    try:
        run_scan(root)
    except Exception as exc:  # never let a thread death be silent
        _set_error(f"scan thread failed: {type(exc).__name__}: {exc}")
    finally:
        _release_lock(root)
        with _state.lock:
            _state.scanning = False
            _state.dirty = False


def is_stale(home: Optional[Path] = None) -> bool:
    """Has anything on disk changed since the cached scan?"""
    with _state.lock:
        if _state.dirty:
            return True
    cache = get_cached(home)
    if cache is None:
        return True
    root = real(home) if home is not None else hermes_home()
    return cache.get("digest") != inventory_digest(build_inventory(root))


def mark_dirty() -> None:
    """A skill changed. Cheap, synchronous, and does not touch the disk."""
    with _state.lock:
        _state.dirty = True


def kick_scan(home: Optional[Path] = None, force: bool = False) -> bool:
    """Start a background scan if one is not already running.

    Returns True when a thread was started. Never blocks the caller, and never
    runs on the hook's thread.
    """
    with _state.lock:
        if _state.scanning:
            return False
        _state.scanning = True
    if not force:
        try:
            if not is_stale(home):
                with _state.lock:
                    _state.scanning = False
                return False
        except Exception:
            pass
    t = threading.Thread(
        target=_scan_worker, args=(home,), name="glance-surfaces-scan", daemon=True
    )
    t.start()
    return True


def new_findings(session_announced: set, home: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Cached findings the agent has not been told about.

    Three filters, in order: severity, baseline, already-announced. Pure
    memory; this is the read path `pre_llm_call` uses.
    """
    cache = get_cached(home)
    if not cache:
        return []
    base = baseline_ids(home)
    out = []
    for f in cache.get("findings", []):
        if f.get("severity") not in AGENT_SEVERITIES:
            continue
        fid = f.get("id")
        if not fid or fid in base or fid in session_announced:
            continue
        out.append(f)
    order = {s: i for i, s in enumerate(AGENT_SEVERITIES)}
    out.sort(key=lambda f: (order.get(f.get("severity"), 9), f.get("path", ""), f.get("line") or 0))
    return out


def stats(home: Optional[Path] = None) -> Dict[str, Any]:
    """Counts and digest for the dashboard. Cache reads only, never a scan."""
    cache = get_cached(home) or {}
    split = findings_by_baseline(home)
    with _state.lock:
        scanning = _state.scanning
        last_error = _state.last_error
    return {
        "scanned_at": cache.get("scanned_at"),
        "digest": cache.get("digest"),
        "policy": cache.get("policy"),
        "engine_version": cache.get("engine_version"),
        "counts": cache.get("counts", {"critical": 0, "high": 0, "medium": 0, "info": 0}),
        "total_scanned": cache.get("total_scanned", 0),
        "baselined": len(baseline_ids(home)),
        # Both sides, always. The status chip is built from `new_counts` alone,
        # so a machine whose only findings are baselined reads green -- but the
        # baselined set stays on the page next to it rather than disappearing.
        "new_counts": _tally(split["new"]),
        "baselined_counts": _tally(split["baselined"]),
        "new": len(split["new"]),
        "new_findings": split["new"],
        "baselined_findings": split["baselined"],
        "warnings": cache.get("warnings", []),
        "scanning": scanning,
        "last_error": last_error,
        "scanner_available": scanner_available(),
    }


def reset_for_tests() -> None:
    with _state.lock:
        _state.cache = None
        _state.scanning = False
        _state.dirty = False
        _state.last_error = None
