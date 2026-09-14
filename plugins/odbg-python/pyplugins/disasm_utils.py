"""Shared disassembly utilities for odbg Python plugins.

Uses capstone if available, otherwise provides a minimal built-in x86-64
length decoder (just enough to skip instructions for xref scanning).
"""

from __future__ import annotations

import odbg

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
    _cs = Cs(CS_ARCH_X86, CS_MODE_64)
    _cs.detail = True
    HAS_CAPSTONE = True
except ImportError:
    _cs = None
    HAS_CAPSTONE = False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def disasm_one(addr: int) -> str:
    """Disassemble a single instruction at `addr`.  Returns a string like
    ``"0x10000:  48 89 5c 24 08    mov [rsp+0x8], rbx"``."""
    data = odbg.read_memory(addr, 15)
    if not data:
        return "%016x  <unreadable>" % addr
    if HAS_CAPSTONE:
        for insn in _cs.disasm(data, addr, count=1):
            return "0x%x:  %-24s  %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str)
    return "0x%x:  %s" % (addr, data[:8].hex())


def disasm_range(addr: int, count: int = 20) -> list[str]:
    """Disassemble `count` instructions starting at `addr`."""
    lines = []
    if HAS_CAPSTONE:
        data = odbg.read_memory(addr, count * 15)
        if not data:
            return ["<unreadable>"]
        for insn in _cs.disasm(data, addr, count=count):
            lines.append("0x%x:  %-24s  %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
        return lines
    # Fallback: use the built-in length decoder
    cur = addr
    for _ in range(count):
        line = disasm_one(cur)
        lines.append(line)
        length = _insn_length(cur)
        if length == 0:
            break
        cur += length
    return lines


def disasm_bytes(addr: int, count: int = 20) -> list[dict]:
    """Disassemble and return structured dicts:
    ``[{"addr": int, "bytes": bytes, "mnemonic": str, "op_str": str}, ...]``."""
    if HAS_CAPSTONE:
        data = odbg.read_memory(addr, count * 15)
        if not data:
            return []
        result = []
        for insn in _cs.disasm(data, addr, count=count):
            result.append({
                "addr": insn.address,
                "bytes": insn.bytes,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            })
        return result
    # Fallback
    cur = addr
    result = []
    for _ in range(count):
        length = _insn_length(cur)
        if length == 0:
            break
        data = odbg.read_memory(cur, length)
        result.append({"addr": cur, "bytes": data or b"", "mnemonic": "?", "op_str": ""})
        cur += length
    return result


# ---------------------------------------------------------------------------
# Minimal x86-64 length decoder (fallback when capstone is missing)
# ---------------------------------------------------------------------------

_X86_64_LEN_TABLE: dict[int, int] = {
    0x00: 2, 0x01: 2, 0x02: 2, 0x03: 2, 0x04: 2, 0x05: 5,
    0x08: 2, 0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 5,
    0x10: 2, 0x11: 2, 0x12: 2, 0x13: 2, 0x14: 2, 0x15: 5,
    0x18: 2, 0x19: 2, 0x1A: 2, 0x1B: 2, 0x1C: 2, 0x1D: 5,
    0x20: 2, 0x21: 2, 0x22: 2, 0x23: 2, 0x24: 2, 0x25: 5,
    0x28: 2, 0x29: 2, 0x2A: 2, 0x2B: 2, 0x2C: 2, 0x2D: 5,
    0x30: 2, 0x31: 2, 0x32: 2, 0x33: 2, 0x34: 2, 0x35: 5,
    0x38: 2, 0x39: 2, 0x3A: 2, 0x3B: 2, 0x3C: 2, 0x3D: 5,
    0x50: 1, 0x51: 1, 0x52: 1, 0x53: 1, 0x54: 1, 0x55: 1,
    0x56: 1, 0x57: 1, 0x58: 1, 0x59: 1, 0x5A: 1, 0x5B: 1,
    0x5C: 1, 0x5D: 1, 0x5E: 1, 0x5F: 1,
    0x68: 5, 0x6A: 2,
    0x74: 2, 0x75: 2, 0x76: 2, 0x77: 2, 0x78: 2, 0x79: 2,
    0x7A: 2, 0x7B: 2, 0x7C: 2, 0x7D: 2, 0x7E: 2, 0x7F: 2,
    0x80: 0, 0x81: 0, 0x83: 0, 0x84: 0, 0x85: 0, 0x88: 0,
    0x89: 0, 0x8A: 0, 0x8B: 0, 0x8D: 0,
    0x90: 1, 0xC0: 0, 0xC1: 0,
    0xC3: 1, 0xC9: 1,
    0xCC: 1, 0xCD: 2,
    0xE8: 5, 0xE9: 5, 0xEB: 2,
    0xF4: 1, 0xF7: 0, 0xFF: 0,
}


def _modrm_length(data: bytes, start: int) -> int:
    """Estimate extra bytes after a ModRM byte at `start`."""
    if start >= len(data):
        return 0
    modrm = data[start]
    mod = (modrm >> 6) & 3
    rm = modrm & 7
    extra = 0
    if mod == 0:
        if rm == 4:
            extra = 1  # SIB
        elif rm == 5:
            extra = 4  # disp32
    elif mod == 1:
        extra = 1  # disp8
        if rm == 4:
            extra = 2  # SIB + disp8
    elif mod == 2:
        extra = 4  # disp32
        if rm == 4:
            extra = 5  # SIB + disp32
    # mod == 3: register direct, no extra
    return extra


def _insn_length(addr: int) -> int:
    data = odbg.read_memory(addr, 15)
    if not data:
        return 0
    b0 = data[0]
    # REX prefix
    if 0x40 <= b0 <= 0x4F:
        data = data[1:]
        b0 = data[0] if data else 0
    known = _X86_64_LEN_TABLE.get(b0)
    if known is not None:
        return known if known > 0 else max(1, 2 + _modrm_length(data, 1))
    # single-byte with ModRM
    return max(1, 2 + _modrm_length(data, 1))
