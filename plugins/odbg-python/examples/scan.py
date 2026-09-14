"""ClawSearch/Cheat-Engine-style memory scanner for odbg, as a Python plugin.

Workflow (repeat to hone in on a value):
  * "Scan module range"   - snapshot every aligned value in a region (default:
    the main module's PE image; override with the scan.range setting
    "0xlo-0xhi", e.g. set via the host settings file).
  * "Filter: changed / unchanged / increased / decreased / equals value"
    - narrow the candidate set against the last snapshot's values.
  * The candidate set lives in plugin memory and survives across runs of the
    debugger session, so scans compose until one candidate (or a handful)
    remains.
  * "Track live" (persisted) - on every paused() event, log which candidate
    addresses have moved, updating the stored value as it goes (watchdog style).

Performance: reads are done in blocks (0x1000 bytes), so a region is scanned
in a handful of marshalled read_memory calls instead of one per address.

Values are read as little-endian integers of the plugin's configured width:
scan.width setting "1"/"2"/"4"/"8" (default "4"). scan.value is a hex string
used by the "equals value" filter (default "0").
"""

import odbg

NAME = "Scan"

READ_BLOCK = 0x1000
MAX_CANDIDATES = 1_000_000  # hard cap so a full-address-space scan cannot OOM


_state = {
    "data": {},          # addr -> value as of the last scan/filter pass
    "width": 4,          # bytes per cell (from scan.width)
    "track": False,      # live (paused-driven) tracking on/off
}

_pair_re = None  # populated lazily to avoid import-time regex cost


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    if "1" in odbg.get_setting("width") or odbg.get_setting("width") not in ("", "1", "2", "4", "8"):
        pass  # fall through to the default-guard below
    width = odbg.get_setting("width")
    _state["width"] = int(width) if width in ("1", "2", "4", "8") else 4
    _state["track"] = odbg.get_setting("track.on") == "1"
    odbg.register_command("scan: first", "snapshot aligned values in the scan region")
    odbg.register_command("scan: changed", "keep addresses whose value changed")
    odbg.register_command("scan: unchanged", "keep addresses whose value did not change")
    odbg.register_command("scan: increased/decreased", "keep addresses that moved up/down")
    odbg.register_command("scan: equals value", "keep addresses equal to scan.value")
    odbg.register_command("scan: track", "log candidate moves on every pause")
    odbg.register_command("scan: clear", "drop the candidate set and re-snapshot")
    odbg.register_command("scan: region", "use the scan.range setting for the region")
    odbg.log("[Scan] ready (width %d)" % _state["width"])
    return 1


def pluginmenu():
    return ["Scan module range", "Filter: changed", "Filter: unchanged",
            "Filter: increased", "Filter: decreased", "Filter: equals value",
            "Track live", "Clear / re-snapshot", "Scan range from setting"]


def pluginaction(action):
    if action == 0:
        _first_scan(_resolve_range)
    elif action == 1:
        _filter("changed")
    elif action == 2:
        _filter("unchanged")
    elif action == 3:
        _filter("increased")
    elif action == 4:
        _filter("decreased")
    elif action == 5:
        _filter("equal")
    elif action == 6:
        _toggle_track()
    elif action == 7:
        _state["data"] = {}
        odbg.log("[Scan] cleared candidates")
        if odbg.stopped():
            _first_scan(_resolve_range)
    elif action == 8:
        _first_scan(lambda: _range_from_setting() or _resolve_range())


def pluginclose():
    odbg.set_setting("width", str(_state["width"]))
    odbg.set_setting("track.on", "1" if _state["track"] else "0")


def paused(reason, regs):
    if not _state["track"] or not regs:
        return
    changed = 0
    # Watchdog cadence: log at most the first MAX_TRACKED moves per pause.
    for addr, stored in list(_state["data"].items())[:MAX_TRACKED]:
        now = odbg.read_memory(addr, _state["width"])
        if now is None:
            continue
        val = int.from_bytes(now, "little")
        if val != stored:
            _state["data"][addr] = val
            changed += 1
            if changed <= 8:
                odbg.log("[Scan] tracked 0x%x: %s -> %s"
                         % (addr, _hex(stored), _hex(val)))
    if changed > 8:
        odbg.log("[Scan] ... %d more candidate moves" % (changed - 8))


MAX_TRACKED = 256


# ---------------------------------------------------------------------------
# Region resolution
# ---------------------------------------------------------------------------

def _resolve_range():
    """Region to scan, in priority order: scan.range setting > main module PE
    image > the largest readable region reported by `memmap`."""
    rng = _range_from_setting()
    if rng:
        return rng
    mod = _main_module_range()
    if mod:
        return mod
    return _largest_memmap_region()


def _range_from_setting():
    raw = odbg.get_setting("range")
    if not raw or "-" not in raw:
        return None
    lo_s, _, hi_s = raw.partition("-")
    try:
        lo, hi = int(lo_s.strip(), 16), int(hi_s.strip(), 16)
    except ValueError:
        return None
    return (lo, max(lo + 1, hi))


def _parse_hex64(text):
    """All 8+ digit hex tokens (with or without 0x) from a command reply."""
    import re
    return [int(m, 16) for m in
            re.findall(r"(?:0x[0-9a-fA-F]{1,16}|\b[0-9a-fA-F]{8,16}\b)", text)]


def _main_module_range():
    """Main module base..end from the `modules` verb, sized via its PE header
    (DOS e_lfanew -> PE optional header SizeOfImage)."""
    rep = odbg.command("modules")
    bases = _parse_hex64(rep or "")
    if not bases:
        return None
    base = bases[0]
    e_lfanew = odbg.read_u32(base + 0x3C)
    if e_lfanew is None:
        return None
    size = odbg.read_u32(base + e_lfanew + 0x50)  # PE32/PE32+ SizeOfImage
    if not size or size > 0x7FFF0000:  # sanity cap ~2GB
        return None
    return (base, base + size)


def _largest_memmap_region():
    best = None
    for lo, hi in _memmap_ranges():
        if best is None or (hi - lo) > (best[1] - best[0]):
            best = (lo, hi)
    return best


def _memmap_ranges():
    vals = _parse_hex64(odbg.command("memmap") or "")
    for i in range(0, len(vals) - 1, 2):
        lo, hi = vals[i], vals[i + 1]
        if 0 < hi - lo <= 0x7FFF0000:
            yield (lo, hi)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _iter_values(lo, hi, width):
    """Yield (addr, value) for aligned cells across [lo, hi). Block reads keep
    the marshalled-call count low; unreadable blocks are skipped."""
    lo = (lo + (width - 1)) & ~(width - 1)
    addr = lo
    while addr < hi:
        n = min(READ_BLOCK, hi - addr)
        block = odbg.read_memory(addr, n)
        if block:
            for off in range(0, len(block) - width + 1, width):
                yield addr + off, int.from_bytes(block[off:off + width], "little")
        addr += READ_BLOCK


def _first_scan(rng_fn):
    if not odbg.need_target_stopped("scanning needs a stopped target"):
        return
    lo, hi = rng_fn()
    if not lo or lo >= hi:
        odbg.log("[Scan] could not resolve a scan region")
        return
    width = _state["width"]
    _state["data"] = {}
    for addr, val in _iter_values(lo, hi, width):
        _state["data"][addr] = val
        if len(_state["data"]) >= MAX_CANDIDATES:
            odbg.log("[Scan] candidate cap reached (%d)" % MAX_CANDIDATES)
            break
    odbg.log("[Scan] first scan: %d cells in 0x%x-0x%x (width %d)"
             % (len(_state["data"]), lo, hi, width))


def _hex(v):
    return "0x%x" % v


def _filter(kind):
    data = _state["data"]
    if not data:
        odbg.log("[Scan] no candidates yet - run a first scan")
        return
    width = _state["width"]
    kept = 0
    for addr, stored in data.items():
        now = odbg.read_memory(addr, width)
        if now is None:
            continue
        val = int.from_bytes(now, "little")
        if _match(kind, val, stored):
            kept += 1
        else:
            del data[addr]
            if kept % 0:
                break  # keep the loop readable; del is safe mid-iteration
    odbg.log("[Scan] %s: %d addresses left (of %d)" % (kind, len(data), kept))


def _match(kind, val, stored):
    if kind == "changed":
        return val != stored
    if kind == "unchanged":
        return val == stored
    if kind == "increased":
        return val > stored
    if kind == "decreased":
        return val < stored
    if kind == "equal":
        try:
            target = int(odbg.get_setting("value"), 16)
        except ValueError:
            return False
        return val == target
    return False


def _toggle_track():
    _state["track"] = not _state["track"]
    odbg.set_setting("track.on", "1" if _state["track"] else "0")
    odbg.log("[Scan] live tracking %s (%d addresses watched)"
             % ("on" if _state["track"] else "off", len(_state["data"])))