"""Shared PE (Portable Executable) utilities for odbg Python plugins.

All functions take a module base address and use the odbg SDK to read
structures.  Call ``refresh_modules()`` once when the target is stopped
to populate the module cache; subsequent calls use the cache.

Usage from a plugin::

    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from pe_utils import resolve, modules, get_sections, get_exports, get_imports
"""

from __future__ import annotations

import odbg

# ---------------------------------------------------------------------------
# Module enumeration (PEB → InLoadOrderModuleList)
# ---------------------------------------------------------------------------

_modules: list[tuple[int, int, str]] = []  # (base, end, name)


def refresh_modules() -> list[tuple[int, int, str]]:
    global _modules
    _modules = []
    peb = odbg.get_peb()
    if not peb:
        return _modules
    ldr = odbg.read_ptr(peb + 0x18)  # PEB.Ldr
    if not ldr:
        return _modules
    # Walk InLoadOrderModuleList. x64 LDR_DATA_TABLE_ENTRY offsets:
    #   0x00 InLoadOrderLinks   0x30 DllBase   0x40 SizeOfImage
    #   0x50 FullDllName.Buffer 0x60 BaseDllName.Buffer
    head = ldr + 0x10                       # InLoadOrderModuleList (a LIST_ENTRY)
    cur = odbg.read_ptr(head)               # first entry's InLoadOrderLinks.Flink
    seen: set[int] = set()
    for _ in range(512):
        if not cur or cur == head or cur in seen:
            break
        seen.add(cur)
        entry = cur                          # InLoadOrderLinks is at entry+0x00
        base = odbg.read_ptr(entry + 0x30)   # DllBase
        size = odbg.read_u32(entry + 0x40)   # SizeOfImage
        name_ptr = odbg.read_ptr(entry + 0x50)  # FullDllName.Buffer
        name = odbg.read_ustr(name_ptr, 260) if name_ptr else ""
        if not name:
            bn = odbg.read_ptr(entry + 0x60)    # BaseDllName.Buffer
            name = odbg.read_ustr(bn, 128) if bn else "?"
        if base:
            if not size or size >= 0x7FFF0000:
                size = _pe_size_of_image(base)
            _modules.append((base, base + size, name))
        cur = odbg.read_ptr(cur)             # next Flink
    return _modules


def modules() -> list[tuple[int, int, str]]:
    if not _modules:
        refresh_modules()
    return list(_modules)


def main_module() -> tuple[int, int, str] | None:
    mods = modules()
    return mods[0] if mods else None


# ---------------------------------------------------------------------------
# Address resolution
# ---------------------------------------------------------------------------

def resolve(addr: int) -> str:
    for base, end, name in modules():
        if base <= addr < end:
            short = name.rsplit("\\", 1)[-1] if "\\" in name else name
            return "%s+0x%x" % (short, addr - base)
    return "0x%x" % addr


def resolve_module(name_part: str) -> tuple[int, int, str] | None:
    low = name_part.lower()
    for base, end, name in modules():
        if low in name.lower():
            return (base, end, name)
    return None


# ---------------------------------------------------------------------------
# PE structure parsing
# ---------------------------------------------------------------------------

def _pe_size_of_image(base: int) -> int:
    e_lfanew = odbg.read_u32(base + 0x3C)
    if not e_lfanew:
        return 0x10000
    magic = odbg.read_u16(base + e_lfanew + 0x18)
    size_off = 0x50 if magic == 0x10B else 0x50  # same offset in both PE32/PE32+
    size = odbg.read_u32(base + e_lfanew + size_off)
    return size if size and size < 0x7FFF0000 else 0x10000


def pe_base(base: int) -> int | None:
    e_lfanew = odbg.read_u32(base + 0x3C)
    return (base + e_lfanew) if e_lfanew else None


def pe_magic(base: int) -> int:
    sig = pe_base(base)
    return odbg.read_u16(sig + 0x18) if sig else 0


def get_sections(base: int) -> list[dict]:
    sig = pe_base(base)
    if not sig:
        return []
    magic = odbg.read_u16(sig + 0x18)
    is_64 = (magic == 0x20B)
    num_sections = odbg.read_u16(sig + 0x06)
    opt_size = odbg.read_u16(sig + 0x14)
    section_off = sig + 0x18 + opt_size
    sections = []
    for i in range(num_sections):
        sa = section_off + i * 40
        name_raw = odbg.read_memory(sa, 8)
        name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace") if name_raw else "?"
        vsize = odbg.read_u32(sa + 8)
        va = odbg.read_u32(sa + 12)
        rsize = odbg.read_u32(sa + 16)
        roff = odbg.read_u32(sa + 20)
        chars = odbg.read_u32(sa + 36)
        sections.append({
            "name": name, "va": va, "vsize": vsize,
            "raw_off": roff, "raw_size": rsize, "chars": chars,
            "executable": bool(chars & 0x20000000),
            "readable": bool(chars & 0x40000000),
            "writable": bool(chars & 0x80000000),
            "rva": base + va,
        })
    return sections


def section_containing(base: int, addr: int) -> dict | None:
    for s in get_sections(base):
        if base + s["va"] <= addr < base + s["va"] + s["vsize"]:
            return s
    return None


# ---------------------------------------------------------------------------
# Import table
# ---------------------------------------------------------------------------

def get_imports(base: int) -> list[dict]:
    sig = pe_base(base)
    if not sig:
        return []
    magic = odbg.read_u16(sig + 0x18)
    is_64 = (magic == 0x20B)
    dd_off = 0x88 if is_64 else 0x78
    imp_rva = odbg.read_u32(sig + dd_off)
    if not imp_rva:
        return []
    imp_va = base + imp_rva
    thunk_sz = 8 if is_64 else 4
    result = []
    idx = 0
    while idx < 256:
        oft_rva = odbg.read_u32(imp_va + idx * 20)
        name_rva = odbg.read_u32(imp_va + idx * 20 + 12)
        iat_rva = odbg.read_u32(imp_va + idx * 20 + 16)
        if not oft_rva and not name_rva:
            break
        dll_name = odbg.read_cstr(base + name_rva, 260) if name_rva else "?"
        thunks = []
        thunk_va = base + (oft_rva if oft_rva else iat_rva)
        ti = 0
        while ti < 1024:
            tv = odbg.read_ptr(thunk_va + ti * thunk_sz)
            if not tv:
                break
            if tv & (1 << (thunk_sz * 8 - 1)):
                thunks.append({"ordinal": tv & 0xFFFF, "name": None})
            else:
                hint_rva = tv & 0x7FFFFFFF
                hint = odbg.read_u16(base + hint_rva) if hint_rva else 0
                fn_name = odbg.read_cstr(base + hint_rva + 2, 200) if hint_rva else "?"
                resolved = odbg.read_ptr(base + iat_rva + ti * thunk_sz) if iat_rva else 0
                thunks.append({"name": fn_name, "hint": hint, "resolved": resolved})
            ti += 1
        result.append({"dll": dll_name, "thunks": thunks})
        idx += 1
    return result


# ---------------------------------------------------------------------------
# Export table
# ---------------------------------------------------------------------------

def get_exports(base: int) -> list[dict]:
    sig = pe_base(base)
    if not sig:
        return []
    magic = odbg.read_u16(sig + 0x18)
    dd_off = 0x98 if magic == 0x20B else 0x88
    exp_rva = odbg.read_u32(sig + dd_off)
    if not exp_rva:
        return []
    exp_va = base + exp_rva
    num_names = odbg.read_u32(exp_va + 20)
    num_funcs = odbg.read_u32(exp_va + 24)
    funcs_rva = odbg.read_u32(exp_va + 28)
    names_rva = odbg.read_u32(exp_va + 32)
    ords_rva = odbg.read_u32(exp_va + 36)
    base_ord = odbg.read_u32(exp_va + 16)
    # Defensive cap: a bad base yields garbage counts; never loop unbounded and
    # freeze the debugger reading millions of phantom entries.
    _MAX = 65536
    if not num_funcs or num_funcs > _MAX or num_names > _MAX:
        return []
    ord_name: dict[int, str] = {}
    for i in range(num_names or 0):
        fn_rva = odbg.read_u32(base + names_rva + i * 4)
        ord_idx = odbg.read_u16(base + ords_rva + i * 2)
        name = odbg.read_cstr(base + fn_rva, 200) if fn_rva else "?"
        ord_name[ord_idx] = name
    result = []
    for i in range(num_funcs):
        func_rva = odbg.read_u32(base + funcs_rva + i * 4)
        ordinal = base_ord + i
        name = ord_name.get(i, None)
        va = base + func_rva if func_rva else 0
        result.append({"ordinal": ordinal, "name": name, "rva": func_rva, "va": va})
    return result
