"""AOB (array-of-bytes) pattern scanner with wildcard support.

Scan memory block-by-block for a byte pattern.  Pattern syntax uses hex
pairs separated by spaces; ``??`` matches any byte.  Examples:

    90 90 90 90          — four NOPs
    48 89 5C 24 ??       — mov [rsp+??], rbx
    E8 ?? ?? ?? ??       — call rel32 (any target)
    CC CC CC CC          — INT3 padding

All candidate regions from the module list are scanned.  Results are
logged one address at a time, capped at MAX_RESULTS.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
import odbg
from pe_utils import modules, refresh_modules
from mem_utils import find_bytes

NAME = "BytePattern"

MAX_RESULTS = 512
BLOCK = 0x1000


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("bpat: scan", "scan all readable memory for a byte pattern")
    odbg.log("[BytePattern] ready")
    return 1


def pluginmenu():
    return ["Scan pattern (setting: bpat.pattern)",
            "Last 10 results",
            "Clear results"]


_results = []
_last_pattern = ""


def pluginaction(action):
    if action == 0:
        _do_scan()
    elif action == 1:
        _show_last()
    elif action == 2:
        _results.clear()
        odbg.log("[BytePattern] results cleared")


def _parse_pattern(text):
    tokens = text.strip().split()
    out = []
    wild = set()
    for i, tok in enumerate(tokens):
        if tok.lower() == "??":
            out.append(0)
            wild.add(i)
        else:
            out.append(int(tok, 16))
    return bytes(out), wild


def _scan_wildcard(start, end, pat, wild):
    """Scan with wildcards using read_memory + manual matching."""
    results = []
    off = start & ~(BLOCK - 1)
    while off < end and len(results) < MAX_RESULTS:
        n = min(BLOCK, end - off)
        data = odbg.read_memory(off, n)
        if data:
            for i in range(len(data) - len(pat) + 1):
                if all(j in wild or data[i + j] == pat[j] for j in range(len(pat))):
                    results.append(off + i)
                    if len(results) >= MAX_RESULTS:
                        break
        off += BLOCK
    return results


def _do_scan():
    if not odbg.need_target_stopped("BytePattern needs a stopped target"):
        return
    raw = odbg.get_setting("pattern")
    if not raw:
        odbg.log("[BytePattern] set bpat.pattern first (e.g. 90 90 90 90)")
        return
    pat, wild = _parse_pattern(raw)
    _results.clear()
    _last_pattern = raw
    total = 0
    for base, end, name in modules():
        hits = _scan_wildcard(base, end, pat, wild)
        _results.extend(hits)
        total += len(hits)
        if len(_results) >= MAX_RESULTS:
            break
    odbg.log("[BytePattern] pattern '%s': %d hits" % (raw, len(_results)))
    for a in _results[:10]:
        odbg.log("[BytePattern]   0x%x" % a)


def _show_last():
    if not _results:
        odbg.log("[BytePattern] no results yet")
        return
    odbg.log("[BytePattern] last %d results:" % min(10, len(_results)))
    for a in _results[-10:]:
        odbg.log("[BytePattern]   0x%x" % a)
