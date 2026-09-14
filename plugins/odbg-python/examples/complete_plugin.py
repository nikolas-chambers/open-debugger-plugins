"""Complete Python plugin example for odbg.

This is the Python twin of the C++ reference plugin in the SDK
(plugins/odbg-sample_plugin/odbg-sample_plugin.cpp): it exercises every
function in the odbg python_sdk in one file, so a plugin author sees how each
SDK call is meant to be used. Copy it (or any plugin) into the bridge's
``pyplugins/`` folder and reload from the Plugins menu.

Whatever this does, a real plugin should do more of the same - drive verbs
through ``odbg.command()``, read registers/memory, react to ``paused``.
"""

import odbg

NAME = "PyExample"

# Settings persist across debugger runs via the host's settings file.
DEFAULT_CHATTY = True


def _chatty():
    return odbg.get_setting("chatty") != "0"


def plugindata():
    return odbg.ABI_VERSION


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0

    odbg.register_command("pyexample: Dump state", "Log registers, PEB and bytes at RIP")
    odbg.register_command("pyexample: Set RAX=0", "Demonstrates odbg.set_reg")
    odbg.register_command("pyexample: Step", "Single-step the target (odbg.step_into)")
    odbg.register_command("pyexample: Go", "Resume the target (odbg.go)")
    odbg.register_command("pyexample: BP NtTerminateProcess",
                          "Add a deferred breakpoint (odbg.add_breakpoint)")
    odbg.register_command("pyexample: Toggle chatty", "Persisted setting")

    # First run has no stored value; treat "" as the default.
    if not odbg.get_setting("chatty"):
        odbg.set_setting("chatty", "1" if DEFAULT_CHATTY else "0")

    odbg.log("[python:PyExample] initialised - exercises the whole python_sdk")
    return 1


def pluginmenu():
    return ["Dump state", "Set RAX = 0", "Step into", "Go",
            "BP NtTerminateProcess", "Toggle chatty"]


def pluginaction(action):
    if action == 0:
        _dump_state()
    elif action == 1:
        _set_rax()
    elif action == 2:
        _step()
    elif action == 3:
        _go()
    elif action == 4:
        _bp_terminate()
    elif action == 5:
        _toggle_chatty()


def paused(reason, regs):
    # Guard it with the persisted setting to stay quiet until toggled on.
    if not _chatty():
        return
    odbg.log("[PyExample] paused (%s) at rip=0x%x"
             % (odbg.reason_name(reason), regs.rip))


def pluginclose():
    odbg.set_setting("chatty", "1" if _chatty() else "0")
    odbg.log("[PyExample] closing")


# ---------------------------------------------------------------------------
# Menu handlers
# ---------------------------------------------------------------------------

def _dump_state():
    if not odbg.need_target_stopped("state dump needs registers"):
        return

    regs = odbg.get_regs()
    odbg.log("[PyExample] rip=0x%x rsp=0x%x rax=0x%x rcx=0x%x rdx=0x%x"
             % (regs.rip, regs.rsp, regs.rax, regs.rcx, regs.rdx))

    # Bytes at the instruction pointer, like the C++ sample's hex dump.
    code = odbg.read_memory(regs.rip, 16)
    if code is not None:
        odbg.log("[PyExample] bytes @ rip: " + " ".join("%02x" % b for b in code))

    # The PEB - the anti-anti-debug plugin patches fields here (see
    # plugins/odbg-anti_anti). BeingDebugged lives at PEB+0x02 on x64.
    peb = odbg.get_peb()
    odbg.log("[PyExample] PEB = 0x%x" % peb)
    if peb:
        bd = odbg.read_u8(peb + 0x02)
        odbg.log("[PyExample] PEB.BeingDebugged = %d" % bd)

    # Drive the full verb surface through the dispatcher - same channel the
    # GUI command bar and the named pipe use (see CONTROL.md).
    odbg.log("[PyExample] command('eval rip+10') = %s"
             % odbg.command("eval rip+10"))

    # Read a NUL-terminated string off the stack (demo of read_cstr).
    cstr = odbg.read_cstr(regs.rsp)
    odbg.log("[PyExample] cstr @ rsp = %r" % cstr)


def _set_rax():
    if not odbg.need_target_stopped("writing a register needs a stopped target"):
        return
    odbg.set_reg("rax", 0)
    # Harmless scribble on the stack top to demonstrate memory writes.
    odbg.write_memory(odbg.get_reg("rsp"), b"\x90")
    odbg.log("[PyExample] set RAX=0 and wrote 0x90 at RSP")


def _step():
    if not odbg.session_active():
        odbg.log("[PyExample] no target")
        return
    odbg.step_into()
    odbg.log("[PyExample] stepped into")


def _go():
    if not odbg.session_active():
        odbg.log("[PyExample] no target")
        return
    odbg.go()
    odbg.log("[PyExample] resumed")


_last_bp = -1


def _bp_terminate():
    if not odbg.session_active():
        odbg.log("[PyExample] no target")
        return
    global _last_bp
    if _last_bp >= 0:
        odbg.remove_breakpoint(_last_bp)
        _last_bp = -1
    # Deferred breakpoint - resolves when the module loads.
    _last_bp = odbg.add_breakpoint("ntdll!NtTerminateProcess")
    odbg.log("[PyExample] breakpoint id=%d on ntdll!NtTerminateProcess" % _last_bp)


def _toggle_chatty():
    # Write it through immediately so it survives the host being killed,
    # not only a clean exit.
    now = not _chatty()
    odbg.set_setting("chatty", "1" if now else "0")
    odbg.log("[PyExample] chatty %s (remembered)" % ("on" if now else "off"))