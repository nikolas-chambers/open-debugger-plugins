"""Basic Windows heap inspector.

Reads the process heap handle from PEB->ProcessHeap and walks the
segment heap header looking for allocation entries.  Works best with
the NT heap; segment heap (Win10+) is partially supported.

This is intentionally lightweight — a full heap walker is a large
project.  This gives a useful "what's in the heap" overview without
needing DbgEng's own heap commands.
"""

import odbg

NAME = "Heap"

MAX_ENTRIES = 200


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("heap: info", "show basic heap info")
    odbg.register_command("heap: scan", "scan heap for interesting patterns")
    odbg.log("[Heap] ready")
    return 1


def pluginmenu():
    return ["Heap info (ProcessHeap)",
            "Scan heap for patterns",
            "Scan heap (setting: heap.pattern)"]


def pluginaction(action):
    if action == 0:
        _heap_info()
    elif action == 1:
        _heap_scan(b"")
    elif action == 2:
        raw = odbg.get_setting("pattern")
        if not raw:
            odbg.log("[Heap] set heap.pattern first (hex bytes)")
            return
        try:
            pat = bytes.fromhex(raw.replace(" ", ""))
        except ValueError:
            odbg.log("[Heap] invalid hex pattern")
            return
        _heap_scan(pat)


def _heap_info():
    if not odbg.need_target_stopped("Heap needs a stopped target"):
        return
    peb = odbg.get_peb()
    if not peb:
        odbg.log("[Heap] cannot read PEB")
        return
    # PEB+0x30 on x64 = ProcessHeap (HANDLE)
    heap_handle = odbg.read_ptr(peb + 0x30)
    odbg.log("[Heap] ProcessHeap handle: 0x%x" % heap_handle)
    if not heap_handle:
        return
    # _HEAP segment header: first QWORD is Seg0RegionLength
    # Real heap structures are complex; read a few fields for overview
    # _HEAP + 0x00 = Segment0 (RTL_CRITICAL_SECTION pointer)
    # _HEAP + 0x40 (Win10) = SegmentSignature (0xDDEEDDFF for NT heap)
    sig = odbg.read_u32(heap_handle + 0x40)
    odbg.log("[Heap] SegmentSignature: 0x%08x %s" % (sig,
        "(NT heap)" if sig == 0xDDEEDDFF else "(unknown/segment heap)"))
    # ListHeaps on x64: walk PEB->ProcessHeaps if we can
    # (not standard; just show the single ProcessHeap for now)
    # Also read the committed size from _HEAP header
    flags = odbg.read_u32(heap_handle + 0x44)
    odbg.log("[Heap] Flags: 0x%08x" % flags)


def _heap_scan(pat):
    if not odbg.need_target_stopped("Heap needs a stopped target"):
        return
    peb = odbg.get_peb()
    heap_handle = odbg.read_ptr(peb + 0x30) if peb else 0
    if not heap_handle:
        odbg.log("[Heap] no heap handle")
        return
    BLOCK = 0x1000
    count = 0
    start = heap_handle & ~0xFFFF
    end = min(start + 0x1000000, 0x7FFFFFFFFFFF)
    odbg.log("[Heap] scanning 0x%x..0x%x for pattern (%d bytes)..."
             % (start, end, len(pat)))
    addr = start
    while addr < end and count < MAX_ENTRIES:
        data = odbg.read_memory(addr, BLOCK)
        if not data:
            addr += BLOCK
            continue
        if pat:
            idx = 0
            while True:
                idx = data.find(pat, idx)
                if idx < 0:
                    break
                odbg.log("[Heap]   match at 0x%x" % (addr + idx))
                count += 1
                idx += 1
                if count >= MAX_ENTRIES:
                    break
        else:
            # No pattern: just log the first few non-zero blocks
            non_zero = sum(1 for b in data[:256] if b != 0)
            if non_zero > 100:
                odbg.log("[Heap]   busy block at 0x%x (%d/256 non-zero bytes)" % (addr, non_zero))
                count += 1
        addr += BLOCK
    odbg.log("[Heap] scan done, %d hits" % count)
