"""Walk the x64 stack and resolve each return address to module+offset.

Walks the RSP chain: reads pointers from RSP up to RBP (or a max depth),
resolves each to a loaded module via the PEB InLoadOrderModuleList, and
logs the stack frame.  Optionally records the walk to a log file.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
import odbg
from pe_utils import resolve, refresh_modules

NAME = "StackWalk"

MAX_DEPTH = 64


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("stkw: walk", "walk the current thread's stack")
    odbg.register_command("stkw: refresh", "refresh module list cache")
    odbg.log("[StackWalk] ready")
    return 1


def pluginmenu():
    return ["Walk stack",
            "Walk + save to file",
            "Refresh modules"]


_walk_log = []


def pluginaction(action):
    if action == 0:
        _walk()
    elif action == 1:
        _walk()
        if _walk_log:
            path = odbg.get_setting("log.path") or "stackwalk.log"
            with open(path, "w") as f:
                for line in _walk_log:
                    f.write(line + "\n")
            odbg.log("[StackWalk] saved %d frames to %s" % (len(_walk_log), path))
    elif action == 2:
        refresh_modules()
        odbg.log("[StackWalk] module cache refreshed")


def _walk():
    if not odbg.need_target_stopped("StackWalk needs a stopped target"):
        return
    _walk_log.clear()
    regs = odbg.get_regs()
    sp = regs.rsp
    bp = regs.rbp
    odbg.log("[StackWalk] RSP=0x%x  RBP=0x%x" % (sp, bp))
    _walk_log.append("--- Stack Walk at RIP=0x%x ---" % regs.rip)
    count = 0
    seen = set()
    while sp < bp or count == 0:
        if count >= MAX_DEPTH:
            break
        if sp in seen or sp == 0:
            break
        seen.add(sp)
        val = odbg.read_ptr(sp)
        if val is None:
            break
        frame = "  [RSP+0x%x] 0x%x  %s" % (sp - regs.rsp, val, resolve(val))
        odbg.log("[StackWalk]" + frame)
        _walk_log.append(frame)
        sp += 8
        count += 1
        if bp and sp > bp + 0x1000:
            break
    odbg.log("[StackWalk] %d frames shown" % count)
