"""Walk the PEB InLoadOrderModuleList and enumerate each module's IAT
(Import Address Table).

For every loaded module, walks the PE import directory and logs each
imported DLL's name + every thunk's function name and resolved address.
Useful for spotting API hooks (compare the IAT entry against the real
export address).
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
import odbg
from pe_utils import modules, get_imports, refresh_modules

NAME = "Imports"


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("imports: dump", "dump IAT of the main module")
    odbg.register_command("imports: dumpall", "dump IAT of every loaded module")
    odbg.log("[Imports] ready")
    return 1


def pluginmenu():
    return ["Dump IAT (main module)",
            "Dump IAT (all modules)",
            "Refresh modules"]


def pluginaction(action):
    if action == 0:
        _dump_main()
    elif action == 1:
        _dump_all()
    elif action == 2:
        refresh_modules()
        odbg.log("[Imports] module cache refreshed")


def _dump_main():
    if not odbg.need_target_stopped("Imports needs a stopped target"):
        return
    mods = modules()
    if not mods:
        odbg.log("[Imports] no modules found")
        return
    base, end, name = mods[0]
    odbg.log("[Imports] --- IAT: %s @ 0x%x ---" % (name, base))
    _dump_imports(base)


def _dump_all():
    if not odbg.need_target_stopped("Imports needs a stopped target"):
        return
    for base, end, name in modules():
        odbg.log("[Imports] --- IAT: %s @ 0x%x ---" % (name, base))
        _dump_imports(base)


def _dump_imports(base):
    for imp in get_imports(base):
        dll = imp["dll"]
        for t in imp["thunks"]:
            if t.get("name"):
                resolved = " -> 0x%x" % t["resolved"] if t.get("resolved") else ""
                odbg.log("[Imports]   %s: %s (hint=%d)%s" % (dll, t["name"], t.get("hint", 0), resolved))
            else:
                odbg.log("[Imports]   %s: ordinal %d" % (dll, t["ordinal"]))
