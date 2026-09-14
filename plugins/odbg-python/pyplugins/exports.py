"""Enumerate DLL exports by name/ordinal with RVAs.

Walks the PE export directory for a given module (default: main module)
and logs every exported symbol's name, ordinal, RVA, and resolved VA.
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
import odbg
from pe_utils import modules, get_exports, refresh_modules

NAME = "Exports"


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("exports: dump", "dump exports of the main module")
    odbg.register_command("exports: dumpall", "dump exports of every loaded module")
    odbg.log("[Exports] ready")
    return 1


def pluginmenu():
    return ["Dump exports (main module)",
            "Dump exports (all modules)",
            "Refresh modules"]


def pluginaction(action):
    if action == 0:
        _dump_main()
    elif action == 1:
        _dump_all()
    elif action == 2:
        refresh_modules()
        odbg.log("[Exports] module cache refreshed")


def _dump_main():
    if not odbg.need_target_stopped("Exports needs a stopped target"):
        return
    mods = modules()
    if not mods:
        odbg.log("[Exports] no modules found")
        return
    base, end, name = mods[0]
    odbg.log("[Exports] --- %s @ 0x%x ---" % (name, base))
    _dump_exports(base)


def _dump_all():
    if not odbg.need_target_stopped("Exports needs a stopped target"):
        return
    for base, end, name in modules():
        odbg.log("[Exports] --- %s @ 0x%x ---" % (name, base))
        _dump_exports(base)


def _dump_exports(base):
    for exp in get_exports(base):
        if exp["name"]:
            odbg.log("[Exports]   ordinal=%d  %-40s  RVA=0x%x  VA=0x%x" %
                     (exp["ordinal"], exp["name"], exp["rva"], exp["va"]))
        else:
            odbg.log("[Exports]   ordinal=%d  (unnamed)                RVA=0x%x  VA=0x%x" %
                     (exp["ordinal"], exp["rva"], exp["va"]))
