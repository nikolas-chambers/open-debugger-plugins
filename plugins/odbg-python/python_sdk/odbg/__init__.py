"""odbg - the python_sdk side of the odbg-python bridge plugin.

This package is what a Python plugin (dropped into the bridge's ``pyplugins``
folder) ``import``s to drive the debugger. Every public name below maps 1:1
onto a host ``Odbg_*`` export (see plugins/open-debugger-plugins_sdk/plugin_sdk/
odbg_plugin_sdk.h); the bridge multiplexes a flat C surface into this package,
and this package makes the surface pleasant from Python.

Two layers:

* ``_odbg``      - the raw C builtin the bridge exposes (thin, untyped).
* this package  - the ergonomic surface Python plugins actually use.

A Python plugin's contract is module-level ``NAME`` plus optional callbacks,
implemented by example in ``examples/`` (see ../README.md). To exercise the
full SDK surface from an interactive interpreter instead of a plugin, the
same functions are usable directly once the bridge has bootstrapped this
package into ``sys.modules``.
"""

from __future__ import annotations

import struct
from collections import namedtuple

try:  # provided by the odbg-python bridge's embedded interpreter
    import _odbg as _host
except ImportError:  # pragma: no cover - only reachable outside the bridge
    _host = None

ABI_VERSION = getattr(_host, "ABI_VERSION", 1) if _host else 1

# Menu origins (Odbg_ORIGIN_*). Only the Plugins menu exists today; the
# parameter stays so a multi-origin menu system can grow without breaking
# existing plugins.
ORIGIN_PLUGINS_MENU = getattr(_host, "ORIGIN_PLUGINS_MENU", 0) if _host else 0

# Reasons handed to the Paused callback.
PAUSE_BREAKPOINT = getattr(_host, "PAUSE_BREAKPOINT", 0) if _host else 0
PAUSE_STEP = getattr(_host, "PAUSE_STEP", 1) if _host else 1
PAUSE_ATTACH_OR_LAUNCH = getattr(_host, "PAUSE_ATTACH_OR_LAUNCH", 2) if _host else 2

REASON_NAMES = {
    PAUSE_BREAKPOINT: "breakpoint",
    PAUSE_STEP: "step",
    PAUSE_ATTACH_OR_LAUNCH: "attach/launch",
}

# Field order matches struct OdbgRegs in the SDK header.
_REG_FIELDS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
               "rbp", "rsp", "rip", "r8", "r9", "r10", "r11")
Regs = namedtuple("Regs", _REG_FIELDS)


def _mod():
    if _host is None:
        raise RuntimeError("odbg python_sdk requires the odbg-python bridge plugin")
    return _host


# ---------------------------------------------------------------------------
# Commands / logging / help
# ---------------------------------------------------------------------------

def command(cmd: str):
    """Run any odbg verb - the exact same dispatcher as the GUI command bar
    and the named pipe (see CONTROL.md). Returns the reply text, or None if
    the host rejected the command."""
    out = _mod().command(str(cmd))
    return None if out is None else out.decode("utf-8", "replace")


def log(text: str) -> None:
    """Append a line to the GUI Log pane, prefixed with the plugin's name."""
    _mod().log(str(text))


def register_command(name: str, help_: str) -> None:
    """Document a plugin-provided command in the Command Reference window."""
    _mod().register_command(str(name), str(help_))


def set_setting(key: str, value: str) -> None:
    """Persist one plugin setting (namespaced per plugin by the host)."""
    _mod().set_setting(str(key), str(value))


def get_setting(key: str) -> str:
    """Read back a persisted plugin setting ("" if never set)."""
    return _mod().get_setting(str(key))


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

def session_active() -> bool:
    """True when a debug session (launched or attached target) exists."""
    return bool(_mod().session_active())


def stopped() -> bool:
    """True when a target exists AND is currently halted (registers valid)."""
    return bool(_mod().stopped())


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

def read_memory(addr: int, size: int):
    """Read `size` bytes from the debuggee. Returns bytes, or None on failure."""
    return _mod().read_memory(int(addr), int(size))


def write_memory(addr: int, data: bytes) -> bool:
    """Write raw bytes into the debuggee. Returns True on success."""
    return bool(_mod().write_memory(int(addr), bytes(data)))


def read_u8(addr: int):
    b = read_memory(addr, 1)
    return None if b is None else b[0]


def read_u16(addr: int):
    b = read_memory(addr, 2)
    return None if b is None else struct.unpack("<H", b)[0]


def read_u32(addr: int):
    b = read_memory(addr, 4)
    return None if b is None else struct.unpack("<I", b)[0]


def read_u64(addr: int):
    b = read_memory(addr, 8)
    return None if b is None else struct.unpack("<Q", b)[0]


read_ptr = read_u64


def read_cstr(addr: int, maxlen: int = 2048) -> str:
    """Read an ASCII/UTF-8 NUL-terminated string from the debuggee."""
    out = bytearray()
    n = 64
    while n <= maxlen:
        chunk = read_memory(addr + len(out), min(64, maxlen - len(out)))
        if not chunk:
            return out.decode("utf-8", "replace")
        end = chunk.find(b"\0")
        if end >= 0:
            out += chunk[:end]
            return out.decode("utf-8", "replace")
        out += chunk
        if len(out) >= maxlen:
            break
        n += 64
    return out.decode("utf-8", "replace")


def read_ustr(addr: int, maxlen: int = 1024) -> str:
    """Read a UTF-16LE NUL-terminated string from the debuggee."""
    raw = bytearray()
    while len(raw) < maxlen:
        chunk = read_memory(addr + len(raw), 64)
        if not chunk:
            break
        end = chunk.find(b"\0\0")
        if end >= 0:
            raw += chunk[:end]
            break
        raw += chunk
    return raw.decode("utf-16-le", "replace")


# ---------------------------------------------------------------------------
# Registers / context
# ---------------------------------------------------------------------------

def get_regs() -> Regs:
    """Whole register file in one call, as a ``Regs`` namedtuple."""
    return Regs(*_mod().get_regs())


def get_reg(name: str) -> int:
    """One register by name (e.g. ``get_reg('rip')``). 0 if it cannot be read."""
    return int(_mod().get_reg(str(name).lower()))


def set_reg(name: str, value: int) -> bool:
    """Write one register. True on success."""
    return bool(_mod().set_reg(str(name).lower(), int(value)))


def get_peb() -> int:
    """The debuggee's Process Environment Block address (0 if unavailable)."""
    return int(_mod().get_peb())


# ---------------------------------------------------------------------------
# Breakpoints
# ---------------------------------------------------------------------------

def add_breakpoint(spec) -> int:
    """Add a breakpoint: ``"kernel32!CreateFileW"`` (deferred) or a hex
    address string. Returns the breakpoint id (or -1 on failure)."""
    return int(_mod().add_breakpoint(str(spec)))


def remove_breakpoint(bp_id: int) -> bool:
    """Remove a breakpoint by id. True on success."""
    return bool(_mod().remove_breakpoint(int(bp_id)))


# ---------------------------------------------------------------------------
# Execution control
# ---------------------------------------------------------------------------

def go() -> None:
    _mod().go()


def pause() -> None:
    _mod().pause()


def step_into() -> None:
    _mod().step_into()


def step_over() -> None:
    _mod().step_over()


# ---------------------------------------------------------------------------
# Small conveniences
# ---------------------------------------------------------------------------

def need_target_stopped(what: str) -> bool:
    """Guard helper for menu actions that need a halted target. Logs why not."""
    if not session_active():
        log("[python] no target")
        return False
    if not stopped():
        log("[python] target is running - " + what)
        return False
    return True


def reason_name(reason: int) -> str:
    return REASON_NAMES.get(reason, str(reason))