"""emulate - a Unicorn-Engine CPU emulator plugin for odbg.

Emulates the debuggee from RIP for N instructions inside Unicorn (the QEMU CPU
core), lazily copying pages of the *live* process into the emulator on demand.
This is the "orchestrate a great free tool" pattern: instead of writing an x86
emulator, we drive Unicorn - and it is the same building block a fast run-trace
engine needs (emulate user code at native-ish speed, escape to the real process
only for syscalls / API calls).

    emu [count]     emulate `count` instructions from RIP (default 32) and
                    report the register delta and where it stopped

Needs Unicorn:  pip install unicorn   (into the interpreter odbg-python embeds)
"""

from __future__ import annotations

import odbg

NAME = "Emulate"

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64,
                         UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UcError)
    from unicorn import x86_const as X
    HAS_UNICORN = True
except Exception:
    HAS_UNICORN = False

_PAGE = 0x1000

# odbg register name -> Unicorn register id. Emulation is seeded from the live
# context so it continues exactly where the debuggee is stopped.
_REGS = None
def _reg_map():
    global _REGS
    if _REGS is None:
        _REGS = {
            "rax": X.UC_X86_REG_RAX, "rbx": X.UC_X86_REG_RBX, "rcx": X.UC_X86_REG_RCX,
            "rdx": X.UC_X86_REG_RDX, "rsi": X.UC_X86_REG_RSI, "rdi": X.UC_X86_REG_RDI,
            "rbp": X.UC_X86_REG_RBP, "rsp": X.UC_X86_REG_RSP, "rip": X.UC_X86_REG_RIP,
            "r8": X.UC_X86_REG_R8, "r9": X.UC_X86_REG_R9, "r10": X.UC_X86_REG_R10,
            "r11": X.UC_X86_REG_R11, "r12": X.UC_X86_REG_R12, "r13": X.UC_X86_REG_R13,
            "r14": X.UC_X86_REG_R14, "r15": X.UC_X86_REG_R15, "efl": X.UC_X86_REG_EFLAGS,
        }
    return _REGS


def plugininit(host_version):
    if HAS_UNICORN:
        odbg.register_verb("emu", _emu_cmd)
        odbg.register_command("emu [count]",
                              "Emulate N instructions from RIP with Unicorn (default 32)")
        odbg.log("[emulate] ready - 'emu [count]' emulates from RIP with Unicorn")
    else:
        odbg.log("[emulate] Unicorn not found - 'pip install unicorn' to enable 'emu'")
    return 1


def pluginmenu():
    return ["Emulate 32 from RIP"] if HAS_UNICORN else []


def pluginaction(action):
    if action == 0:
        odbg.log("[emulate] " + _emu_cmd("32"))


def _emu_cmd(arg):
    if not HAS_UNICORN:
        return "Unicorn not installed (pip install unicorn)"
    if not odbg.session_active() or not odbg.stopped():
        return "emu needs a stopped target"
    try:
        count = int(arg.strip(), 0) if arg.strip() else 32
    except ValueError:
        count = 32

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped = set()

    def ensure(addr):
        base = addr & ~(_PAGE - 1)
        if base in mapped:
            return
        mapped.add(base)
        try:
            uc.mem_map(base, _PAGE)
        except UcError:
            return
        data = odbg.read_memory(base, _PAGE) or b""
        if data:
            uc.mem_write(base, data.ljust(_PAGE, b"\x00"))

    # Copy pages from the live process on demand: when Unicorn faults on an
    # unmapped address, map it, fill it from the debuggee, and retry.
    def on_unmapped(uc_, access, address, size, value, user):
        ensure(address)
        return True

    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

    regs = _reg_map()
    start = odbg.get_reg("rip")
    for name, uid in regs.items():
        try:
            uc.reg_write(uid, odbg.get_reg(name))
        except Exception:
            pass
    ensure(start)
    ensure(odbg.get_reg("rsp"))

    executed = []
    uc.hook_add(UC_HOOK_CODE, lambda u, a, s, x: executed.append(a))

    stopped_reason = "%d instructions" % count
    try:
        uc.emu_start(start, 0, count=count)
    except UcError as e:
        # Emulation halts on something Unicorn can't do here (a syscall, an
        # API call into unmapped code, a fault) - report it; a real trace
        # engine would escape to the live process at this point.
        stopped_reason = "stopped early (%s)" % e

    end_rip = uc.reg_read(regs["rip"])
    end_rax = uc.reg_read(regs["rax"])
    end_rsp = uc.reg_read(regs["rsp"])
    return ("emulated %d insns [%s]  rip %#x -> %#x  rax=%#x rsp=%#x"
            % (len(executed), stopped_reason, start, end_rip, end_rax, end_rsp))
