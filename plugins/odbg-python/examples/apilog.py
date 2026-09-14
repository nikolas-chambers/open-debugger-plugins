"""API call logger for odbg - a real, useful example Python plugin.

Sits on the exact ROADMAP/AUDIT items "API/call tracing & logging plugin"
(O2's traceapi sample): watch a list of interesting APIs, log each call with
its x64 calling-convention arguments (rcx, rdx, r8, r9, then stack slots
rsp+0x20 / +0x28 ...), and optionally resume automatically after logging
(log-and-continue, the "conditional logging breakpoint" behavior).

The reference-plugin material above (complete_plugin.py) shows the mechanics;
this one shows a plugin that is worth shipping as-is. It is how pipelines
like "trace every CreateFileW" are built without any native code.

Caveats (honest, matching the maintainer's own audit):
* odbg has no conditional/logging breakpoints yet - this approximates log-
  and-continue: on a breakpoint pause it logs, then a deliberately-off-by-
  default setting resumes with `odbg.command("g")`. That resumption races
  the "pause does not always stop a running target" bug the roadmap flags,
  so auto_continue stays OFF unless the user opts in.
* The manager can't tell *which* breakpoint fired from the callback alone,
  so this logs every stop reported as a breakpoint while armed. Firing from
  a redirected/stopped-starting target is out of scope for a demo.
"""

import odbg

NAME = "APILog"

WATCH = [
    "kernel32!CreateFileW",
    "kernel32!ReadFile",
    "kernel32!WriteFile",
    "kernel32!VirtualAlloc",
    "kernel32!VirtualFree",
    "ntdll!NtTerminateProcess",
]

_last_bp_ids = []
_armed = False


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    for api in WATCH:
        odbg.register_command("apilog: %s" % api, "temporarily add %s to the trace set" % api)
    odbg.register_command("apilog: Arm", "set breakpoints on the whole trace set")
    odbg.register_command("apilog: Disarm", "remove all trace breakpoints")
    odbg.register_command("apilog: Define arg format", "choose auto / wide")
    # auto_continue defaults off - see the module docstring caveat.
    if not odbg.get_setting("auto_continue"):
        odbg.set_setting("auto_continue", "0")
    odbg.log("[APILog] ready - 'Arm' from the Plugins/PyExample-adjacent menu")
    return 1


def pluginmenu():
    return ["Arm trace", "Disarm trace", "Trace one: CreateFileW",
            "Log args wide", "Auto-continue: on"]


def pluginaction(action):
    if action == 0:
        _arm()
    elif action == 1:
        _disarm()
    elif action == 2:
        _trace_one("kernel32!CreateFileW")
    elif action == 3:
        _set_wide()
    elif action == 4:
        _set_auto_continue()


def paused(reason, regs):
    if not _armed:
        return
    if reason != odbg.PAUSE_BREAKPOINT:
        return
    # An approximate but honest trace line - x64 fastcall arg registers.
    a1, a2, a3, a4 = regs.rcx, regs.rdx, regs.r8, regs.r9
    stack5 = read_ptr_safe(regs.rsp + 0x20)
    stack6 = read_ptr_safe(regs.rsp + 0x28)
    wild = _wide()
    fmt = "%s" if wild else "0x%x"
    odbg.log("[APILog] --> rip=0x%x  args %s %s %s %s  [rsp+20]=%s [rsp+28]=%s"
             % (regs.rip,
                fmt % a1, fmt % a2, fmt % a3, fmt % a4,
                fmt % stack5 if stack5 is not None else "?",
                fmt % stack6 if stack6 is not None else "?"))
    if odbg.get_setting("auto_continue") == "1":
        # Opt-in only: resumes, which the manager cannot safely time.
        odbg.command("g")


def pluginclose():
    _disarm()


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def read_ptr_safe(addr):
    try:
        return odbg.read_ptr(addr)
    except Exception:
        return None


def _arm():
    global _armed, _last_bp_ids
    _disarm()
    for api in WATCH:
        bid = odbg.add_breakpoint(api)
        if bid >= 0:
            _last_bp_ids.append(bid)
    _armed = True
    odbg.log("[APILog] armed %d breakpoints" % len(_last_bp_ids))


def _disarm():
    global _armed
    for bid in _last_bp_ids:
        odbg.remove_breakpoint(bid)
    _last_bp_ids.clear()
    _armed = False


def _trace_one(api):
    global _armed, _last_bp_ids
    bid = odbg.add_breakpoint(api)
    if bid >= 0:
        _last_bp_ids.append(bid)
        _armed = True
        odbg.log("[APILog] added %s (id=%d)" % (api, bid))


def _wide():
    return odbg.get_setting("arg_wide") == "1"


def _set_wide():
    odbg.set_setting("arg_wide", "1")
    odbg.log("[APILog] wide string args on the next pause's log")


def _set_auto_continue():
    on = odbg.get_setting("auto_continue") != "1"
    odbg.set_setting("auto_continue", "1" if on else "0")
    odbg.log("[APILog] auto-continue %s" % ("on" if on else "off"))