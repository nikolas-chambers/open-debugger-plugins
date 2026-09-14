"""Cross-reference finder: scan loaded code for LEA/MOV/CALL/JMP referencing
a given address.

Scans the entire code region(s) of loaded modules looking for x86-64
instructions that encode a reference to the target address.  Handles
RIP-relative instructions (E8/E9 rel32, 0F 8x Jcc rel32, 8D/8B/89
LEA/MOV with ModRM RIP-relative).
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
import odbg
from pe_utils import modules, refresh_modules

NAME = "XRef"

MAX_RESULTS = 256


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("xref: find", "find cross-references to an address")
    odbg.log("[XRef] ready")
    return 1


def pluginmenu():
    return ["Find xrefs to (setting: xref.addr)",
            "Find xrefs to RIP",
            "Refresh modules"]


def pluginaction(action):
    if action == 0:
        raw = odbg.get_setting("addr")
        if not raw:
            odbg.log("[XRef] set xref.addr first (hex address)")
            return
        try:
            target = int(raw, 16)
        except ValueError:
            odbg.log("[XRef] invalid address: %s" % raw)
            return
        _find_xrefs(target)
    elif action == 1:
        regs = odbg.get_regs()
        _find_xrefs(regs.rip)
    elif action == 2:
        refresh_modules()
        odbg.log("[XRef] module cache refreshed")


def _find_xrefs(target):
    if not odbg.need_target_stopped("XRef needs a stopped target"):
        return
    results = []
    BLOCK = 0x10000
    for base, end, name in modules():
        addr = base
        while addr < end and len(results) < MAX_RESULTS:
            n = min(BLOCK, end - addr)
            data = odbg.read_memory(addr, n)
            if not data:
                addr += n
                continue
            _scan_block(data, addr, target, results)
            addr += n
    if not results:
        odbg.log("[XRef] no xrefs to 0x%x found" % target)
        return
    odbg.log("[XRef] %d xrefs to 0x%x:" % (len(results), target))
    from pe_utils import resolve
    for rip, kind in results:
        odbg.log("[XRef]   %s  %s" % (resolve(rip), kind))


def _scan_block(data, base, target, results):
    n = len(data)
    for i in range(n - 4):
        byte = data[i]
        if byte == 0xE8:
            rel = int.from_bytes(data[i+1:i+5], "little", signed=True)
            if base + i + 5 + rel == target:
                results.append((base + i, "call"))
                if len(results) >= MAX_RESULTS: return
        elif byte == 0xE9:
            rel = int.from_bytes(data[i+1:i+5], "little", signed=True)
            if base + i + 5 + rel == target:
                results.append((base + i, "jmp"))
                if len(results) >= MAX_RESULTS: return
        elif byte == 0x0F and i + 6 <= n and 0x80 <= data[i+1] <= 0x8F:
            rel = int.from_bytes(data[i+2:i+6], "little", signed=True)
            if base + i + 6 + rel == target:
                results.append((base + i, "jcc"))
                if len(results) >= MAX_RESULTS: return
        elif byte in (0x8D, 0x8B, 0x89) and i + 6 <= n and (data[i+1] & 0xC7) == 0x05:
            rel = int.from_bytes(data[i+2:i+6], "little", signed=True)
            if base + i + 6 + rel == target:
                kind = "lea" if byte == 0x8D else "mov"
                results.append((base + i, kind))
                if len(results) >= MAX_RESULTS: return
