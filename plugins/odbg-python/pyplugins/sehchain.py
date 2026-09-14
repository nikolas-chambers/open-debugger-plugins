"""Walk the x64 SEH/VEH handler chain from the Thread Information Block.

On x64 Windows, the structured exception handling chain is rooted at
GS:[0x30] (Teb->ExceptionList).  Since GS-base isn't directly accessible
from the SDK, we do a best-effort RSP heuristic scan for handler pointers
and also dump the host's exception settings.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
import odbg
from pe_utils import resolve, refresh_modules

NAME = "SEHChain"

MAX_CHAIN = 64


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("seh: chain", "walk the SEH handler chain")
    odbg.log("[SEHChain] ready")
    return 1


def pluginmenu():
    return ["Walk SEH chain",
            "Show VEH handlers"]


def pluginaction(action):
    if action == 0:
        _walk_seh()
    elif action == 1:
        _show_veh()


def _walk_seh():
    if not odbg.need_target_stopped("SEHChain needs a stopped target"):
        return
    refresh_modules()
    regs = odbg.get_regs()
    odbg.log("[SEHChain] SEH walk (RSP heuristic):")
    sp = regs.rsp
    found = 0
    for off in range(0, min(0x400, 0x7FFF0000 - sp), 8):
        handler = odbg.read_ptr(sp + off + 8)
        if handler and 0x10000 < handler < 0x7FFFFFFFFFFF:
            odbg.log("[SEHChain]   RSP+0x%x: Handler=0x%x  %s" % (off, handler, resolve(handler)))
            found += 1
            if found >= MAX_CHAIN:
                break
    if not found:
        odbg.log("[SEHChain]   (no SEH frames found via RSP heuristic)")


def _show_veh():
    if not odbg.need_target_stopped("SEHChain needs a stopped target"):
        return
    rep = odbg.command("exceptions")
    odbg.log("[SEHChain] exception settings:")
    for line in (rep or "").split("\n"):
        odbg.log("[SEHChain]   " + line.strip())
