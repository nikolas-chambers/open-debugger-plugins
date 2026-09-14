"""Shared memory utilities for odbg Python plugins.

Pointer chain walking, binary diff, string search, memory dump, and
pattern scanning — all built on the odbg SDK's read_memory / read_ptr.
"""

from __future__ import annotations

import odbg

# ---------------------------------------------------------------------------
# Pointer chain walking
# ---------------------------------------------------------------------------

def pointer_chain(base: int, offsets: list[int]) -> int | None:
    """Follow a multi-level pointer chain: base + offsets[0] → read ptr,
    + offsets[1] → read ptr, ...  Returns the final address or None."""
    addr = base
    for off in offsets:
        val = odbg.read_ptr(addr + off)
        if val is None or val == 0:
            return None
        addr = val
    return addr


def pointer_chain_value(base: int, offsets: list[int], width: int = 4) -> int | None:
    """Walk a pointer chain and read the final value as an integer."""
    addr = pointer_chain(base, offsets)
    if addr is None:
        return None
    if width == 1:
        v = odbg.read_u8(addr)
    elif width == 2:
        v = odbg.read_u16(addr)
    elif width == 8:
        v = odbg.read_u64(addr)
    else:
        v = odbg.read_u32(addr)
    return v


# ---------------------------------------------------------------------------
# Binary diff
# ---------------------------------------------------------------------------

def binary_diff(addr_a: int, addr_b: int, size: int, block: int = 0x1000) -> list[dict]:
    """Compare two memory regions byte-by-byte.  Returns a list of
    ``{"offset": int, "a": int, "b": int}`` for each differing byte.
    Capped at 1000 differences."""
    diffs = []
    off = 0
    while off < size and len(diffs) < 1000:
        n = min(block, size - off)
        data_a = odbg.read_memory(addr_a + off, n)
        data_b = odbg.read_memory(addr_b + off, n)
        if not data_a or not data_b:
            off += n
            continue
        for i in range(min(len(data_a), len(data_b))):
            if data_a[i] != data_b[i]:
                diffs.append({"offset": off + i, "a": data_a[i], "b": data_b[i]})
                if len(diffs) >= 1000:
                    break
        off += n
    return diffs


# ---------------------------------------------------------------------------
# String search
# ---------------------------------------------------------------------------

def find_strings(addr: int, size: int, encoding: str = "ascii",
                 min_len: int = 4, block: int = 0x1000) -> list[dict]:
    """Scan a memory region for null-terminated strings.  Returns
    ``[{"addr": int, "text": str}, ...]``."""
    enc_map = {
        "ascii": ("ascii", 1),
        "utf-8": ("utf-8", 1),
        "utf-16": ("utf-16-le", 2),
        "utf16": ("utf-16-le", 2),
    }
    codec, unit = enc_map.get(encoding.lower(), ("ascii", 1))
    results = []
    off = 0
    while off < size and len(results) < 500:
        n = min(block, size - off)
        data = odbg.read_memory(addr + off, n)
        if not data:
            off += n
            continue
        cur = bytearray()
        cur_start = off
        for i in range(0, len(data), unit):
            chunk = data[i:i + unit]
            if unit == 1:
                b = chunk[0]
                if b == 0:
                    if len(cur) >= min_len:
                        try:
                            text = bytes(cur).decode(codec, errors="replace")
                        except Exception:
                            text = repr(bytes(cur))
                        results.append({"addr": addr + cur_start, "text": text})
                    cur = bytearray()
                    cur_start = off + i + unit
                elif 0x20 <= b < 0x7F or b >= 0xA0:
                    cur.extend(chunk)
                else:
                    cur = bytearray()
                    cur_start = off + i + unit
            else:  # utf-16
                code = int.from_bytes(chunk, "little")
                if code == 0:
                    if len(cur) >= min_len * unit:
                        try:
                            text = bytes(cur).decode(codec, errors="replace")
                        except Exception:
                            text = repr(bytes(cur))
                        results.append({"addr": addr + cur_start, "text": text})
                    cur = bytearray()
                    cur_start = off + i + unit
                elif 0x20 <= code < 0x7F or code >= 0xA0:
                    cur.extend(chunk)
                else:
                    cur = bytearray()
                    cur_start = off + i + unit
        off += n
    return results


# ---------------------------------------------------------------------------
# Memory dump (hex + ascii)
# ---------------------------------------------------------------------------

def hexdump(addr: int, size: int = 256, width: int = 16) -> list[str]:
    """Return a list of hex-dump lines like ``00007ff6  48 89 5C 24 08  |...|``."""
    lines = []
    off = 0
    while off < size:
        n = min(width, size - off)
        data = odbg.read_memory(addr + off, n)
        if not data:
            lines.append("%016x  <unreadable>" % (addr + off))
            off += width
            continue
        hex_part = " ".join("%02x" % b for b in data)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)
        lines.append("%016x  %-48s  |%s|" % (addr + off, hex_part, ascii_part))
        off += width
    return lines


def dump_to_file(addr: int, size: int, path: str) -> int:
    """Dump raw bytes to a file.  Returns bytes written."""
    written = 0
    with open(path, "wb") as f:
        off = 0
        while off < size:
            n = min(0x1000, size - off)
            data = odbg.read_memory(addr + off, n)
            if data:
                f.write(data)
                written += len(data)
            off += n
    return written


# ---------------------------------------------------------------------------
# Pattern scan (simple bytes, no wildcards — bytepattern.py handles ??)
# ---------------------------------------------------------------------------

def find_bytes(pattern: bytes, start: int, end: int, block: int = 0x1000) -> list[int]:
    """Find all occurrences of a byte pattern in [start, end).
    Returns list of addresses."""
    results = []
    off = start & ~(block - 1)
    while off < end and len(results) < 1000:
        n = min(block, end - off)
        data = odbg.read_memory(off, n)
        if data:
            idx = 0
            while True:
                idx = data.find(pattern, idx)
                if idx < 0:
                    break
                results.append(off + idx)
                idx += 1
        off += block
    return results
