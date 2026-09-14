"""Shared address utilities for odbg Python plugins.

Address resolution, code cave finder, and pointer scanner — all in one
place so plugins don't duplicate logic.
"""

from __future__ import annotations

import odbg
from pe_utils import modules, resolve as resolve_addr, section_containing

# ---------------------------------------------------------------------------
# Code cave finder
# ---------------------------------------------------------------------------

def find_code_caves(min_size: int = 64, max_results: int = 20) -> list[dict]:
    """Scan executable sections for runs of null/INT3 bytes (code caves).
    Returns ``[{"addr": int, "size": int, "type": "null"|"int3"|"mixed"}, ...]``."""
    caves = []
    for base, end, name in modules():
        for section in _sections_for(base):
            if not section["executable"]:
                continue
            sec_start = base + section["va"]
            sec_size = section["vsize"]
            off = 0
            while off < sec_size and len(caves) < max_results:
                n = min(0x1000, sec_size - off)
                data = odbg.read_memory(sec_start + off, n)
                if not data:
                    off += n
                    continue
                run_start = off
                run_type = None
                run_len = 0
                for i in range(len(data)):
                    b = data[i]
                    if b == 0x00:
                        t = "null"
                    elif b == 0xCC:
                        t = "int3"
                    else:
                        t = None
                    if t and (run_type is None or t == run_type):
                        run_type = t
                        run_len += 1
                    else:
                        if run_len >= min_size:
                            caves.append({
                                "addr": sec_start + run_start,
                                "size": run_len,
                                "type": run_type,
                                "section": section["name"],
                            })
                        run_start = off + i + 1
                        run_type = t if t else None
                        run_len = 1 if t else 0
                if run_len >= min_size:
                    caves.append({
                        "addr": sec_start + run_start,
                        "size": run_len,
                        "type": run_type,
                        "section": section["name"],
                    })
                off += n
    return caves


def _sections_for(base: int) -> list[dict]:
    from pe_utils import get_sections
    return get_sections(base)


# ---------------------------------------------------------------------------
# Pointer scanner — find who points to a value
# ---------------------------------------------------------------------------

def scan_for_pointer(target: int, start: int = 0, end: int = 0x7FFFFFFFFFFF,
                     block: int = 0x10000, max_results: int = 100) -> list[int]:
    """Scan memory for QWORDs that equal `target`.  Useful for finding
    back-pointers to a structure.  Returns list of addresses."""
    results = []
    addr = max(start, 0x10000) & ~(block - 1)
    while addr < end and len(results) < max_results:
        data = odbg.read_memory(addr, block)
        if not data:
            addr += block
            continue
        for i in range(0, len(data) - 7, 8):
            if int.from_bytes(data[i:i + 8], "little") == target:
                results.append(addr + i)
                if len(results) >= max_results:
                    break
        addr += block
    return results


def scan_for_dword(target: int, start: int = 0, end: int = 0x7FFFFFFFFFFF,
                   block: int = 0x10000, max_results: int = 100) -> list[int]:
    """Same but 4-byte match."""
    results = []
    addr = max(start, 0x10000) & ~(block - 1)
    while addr < end and len(results) < max_results:
        data = odbg.read_memory(addr, block)
        if not data:
            addr += block
            continue
        for i in range(0, len(data) - 3, 4):
            if int.from_bytes(data[i:i + 4], "little") == target:
                results.append(addr + i)
                if len(results) >= max_results:
                    break
        addr += block
    return results
