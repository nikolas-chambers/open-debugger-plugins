"""One-shot script example: full python_sdk usage in a single main(odbg).

Dropped into the scripts/ folder it shows up in the Plugins menu as
"Run: snapshot" - imported on demand, run, discarded; edit and re-run freely.
This is the script-mode twin of examples/complete_plugin.py (the long-lived
plugin that exercises the same surface with plugin lifecycle callbacks).

Deliberately safe: every mutating step is guarded, and the two bytes it
touches (stack top + a temporary breakpoint) are restored/removed before
returning, so re-running it is idempotent.
"""

import odbg

# Demonstration of a one-shot helper: print a register/memory/PEB snapshot and
# drive a couple of verbs. Takes no persistent state.
def main(odbg):
    odbg.log("== snapshot ==")
    odbg.log("session active: %s   stopped: %s" % (odbg.session_active(), odbg.stopped()))

    if odbg.stopped():
        r = odbg.get_regs()
        odbg.log("rip=0x%x  rsp=0x%x  rax=0x%x  rcx=0x%x  rdx=0x%x"
                 % (r.rip, r.rsp, r.rax, r.rcx, r.rdx))

        # Single byte and a typed word at RIP - exercises read_memory readers.
        op = odbg.read_u8(r.rip)
        op_ptr = odbg.read_ptr(r.rip)
        odbg.log("opcode @ rip=0x%x  first qword=%s" % (op if op is not None else 0,
                                                        "0x%x" % op_ptr if op_ptr is not None else "?"))

        # Drive the full verb surface - the same dispatcher as GUI + pipe
        # (CONTROL.md). eval and goto are the two most useful from scripts.
        odbg.log("command('eval rip+10') = %s" % odbg.command("eval rip+10"))

        # Text search across the address space, then navigate to the hit.
        odbg.command("search 'MZ'")

        # Read-modify-write one byte on the stack top, then restore it.
        saved = odbg.read_u8(r.rsp)
        if saved is not None:
            odbg.write_memory(r.rsp, b"\x90")
            odbg.log("wrote 0x90 @ rsp (was 0x%02x, restored)" % saved)
            odbg.write_memory(r.rsp, bytes([saved]))

        # A single register write, guarded - setting RAX to 0 is harmless.
        odbg.set_reg("rax", 0)
        odbg.log("set rax=0")

        # Add-and-remove a breakpoint while stopped (no lasting state).
        bid = odbg.add_breakpoint("kernel32!CreateFileW")
        odbg.log("temp breakpoint id=%d" % bid)
        if bid >= 0:
            odbg.remove_breakpoint(bid)

        # Persisted per-plugin setting - survives across debugger runs.
        odbg.set_setting("snapshot.last", "0x%x" % r.rip)
        odbg.log("stored snapshot.last = %s" % odbg.get_setting("snapshot.last"))
    else:
        odbg.log("target running or absent - registers/memory unavailable")

    peb = odbg.get_peb()
    if peb:
        bd = odbg.read_u8(peb + 0x02)
        odbg.log("PEB = 0x%x  BeingDebugged = %d" % (peb, bd))

    odbg.log("== end snapshot ==")