"""Record every RIP value on pause to a trace log, with optional filtering.

Stores a sequential list of (rip, reason, cycle) tuples.  Can dump to
file, show recent entries, clear the buffer, or report unique RIP
counts.  Useful for finding hot paths without full single-step tracing.
"""

import odbg

NAME = "Tracer"

MAX_ENTRIES = 100_000
_trace = []
_paused_count = 0
_armed = False


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("trace: start", "start recording RIP on every pause")
    odbg.register_command("trace: stop", "stop recording")
    odbg.register_command("trace: dump", "dump trace to file")
    odbg.register_command("trace: stats", "show unique-RIP summary")
    odbg.log("[Tracer] ready")
    return 1


def pluginmenu():
    return ["Start recording",
            "Stop recording",
            "Show last 20",
            "Dump to file",
            "Unique RIP stats",
            "Clear trace"]


def pluginaction(action):
    global _armed
    if action == 0:
        _armed = True
        odbg.log("[Tracer] recording ON")
    elif action == 1:
        _armed = False
        odbg.log("[Tracer] recording OFF (%d entries)" % len(_trace))
    elif action == 2:
        _show_last(20)
    elif action == 3:
        _dump_file()
    elif action == 4:
        _stats()
    elif action == 5:
        _trace.clear()
        odbg.log("[Tracer] trace cleared")


def paused(reason, regs):
    global _paused_count
    if not _armed or not regs:
        return
    _paused_count += 1
    if len(_trace) < MAX_ENTRIES:
        _trace.append((regs.rip, reason, _paused_count))


def _show_last(n):
    if not _trace:
        odbg.log("[Tracer] no entries yet")
        return
    odbg.log("[Tracer] last %d entries:" % min(n, len(_trace)))
    for rip, reason, cycle in _trace[-n:]:
        odbg.log("[Tracer]   #%d rip=0x%x reason=%s" % (cycle, rip, odbg.reason_name(reason)))


def _dump_file():
    if not _trace:
        odbg.log("[Tracer] nothing to dump")
        return
    path = odbg.get_setting("log.path") or "trace.log"
    with open(path, "w") as f:
        for rip, reason, cycle in _trace:
            f.write("#%d 0x%x %s\n" % (cycle, rip, odbg.reason_name(reason)))
    odbg.log("[Tracer] dumped %d entries to %s" % (len(_trace), path))


def _stats():
    if not _trace:
        odbg.log("[Tracer] no entries yet")
        return
    counts = {}
    for rip, _, _ in _trace:
        counts[rip] = counts.get(rip, 0) + 1
    top = sorted(counts.items(), key=lambda x: -x[1])[:15]
    odbg.log("[Tracer] %d unique RIPs across %d pauses:" % (len(counts), len(_trace)))
    for rip, cnt in top:
        odbg.log("[Tracer]   0x%x  x%d" % (rip, cnt))
