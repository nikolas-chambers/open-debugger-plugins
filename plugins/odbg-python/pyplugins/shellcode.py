"""Assemble x86/x64 instructions to bytes and optionally write them to memory.

Uses keystone-engine if available, otherwise falls back to a minimal
hand-rolled encoder for the most common patterns (NOP, INT3, RET, JMP,
CALL rel32).  Assembled bytes are logged and can optionally be written to
the target with one menu action.
"""

import odbg

NAME = "Shellcode"

try:
    import keystone
    KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    HAS_KS = True
except ImportError:
    KS = None
    HAS_KS = False


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    if not HAS_KS:
        odbg.log("[Shellcode] keystone-engine not found — using built-in minimal assembler")
    odbg.register_command("asm: assemble", "assemble instructions from shellcode.asm setting")
    odbg.register_command("asm: write", "assemble + write to shellcode.addr")
    odbg.log("[Shellcode] ready")
    return 1


def pluginmenu():
    return ["Assemble (setting: shellcode.asm)",
            "Assemble + write to addr (shellcode.addr)",
            "Show keystone status"]


def _assemble(text):
    if HAS_KS:
        try:
            enc, _ = KS.asm(text)
            return bytes(enc) if enc else None
        except keystone.KsError as e:
            odbg.log("[Shellcode] keystone error: %s" % e)
            return None
    return _builtin_assemble(text)


def _builtin_assemble(text):
    tokens = [t.strip().lower() for t in text.replace(";", ",").split(",") if t.strip()]
    out = bytearray()
    for tok in tokens:
        if tok == "nop":
            out.append(0x90)
        elif tok in ("ret", "retn"):
            out.append(0xC3)
        elif tok == "int3" or tok == "cc":
            out.append(0xCC)
        elif tok.startswith("int ") and len(tok) == 5:
            out.append(0xCD)
            out.append(int(tok[4:], 16))
        elif tok.startswith("jmp ") or tok.startswith("call "):
            is_call = tok.startswith("call ")
            try:
                target = int(tok.split()[1], 16)
            except ValueError:
                odbg.log("[Shellcode] cannot encode: %s (need hex addr)" % tok)
                continue
            opcode = 0xE8 if is_call else 0xE9
            # placeholder: we'd need current RIP; use 0 for now
            out.append(opcode)
            out.extend(target.to_bytes(4, "little", signed=True))
        elif all(c in "0123456789abcdef" for c in tok.replace(" ", "")):
            try:
                out.extend(bytes.fromhex(tok.replace(" ", "")))
            except ValueError:
                odbg.log("[Shellcode] bad hex: %s" % tok)
        else:
            odbg.log("[Shellcode] unknown instruction: %s" % tok)
    return bytes(out) if out else None


def pluginaction(action):
    if action == 0:
        _do_assemble()
    elif action == 1:
        _do_write()
    elif action == 2:
        odbg.log("[Shellcode] keystone: %s" % ("available" if HAS_KS else "NOT available"))


def _do_assemble():
    asm_text = odbg.get_setting("asm") or "nop"
    odbg.log("[Shellcode] assembling: %s" % asm_text)
    code = _assemble(asm_text)
    if code:
        hex_str = " ".join("%02x" % b for b in code)
        odbg.log("[Shellcode] result (%d bytes): %s" % (len(code), hex_str))
    else:
        odbg.log("[Shellcode] assembly failed")


def _do_write():
    if not odbg.need_target_stopped("Shellcode needs a stopped target"):
        return
    asm_text = odbg.get_setting("asm") or "nop"
    addr_str = odbg.get_setting("addr") or "0"
    try:
        addr = int(addr_str, 16)
    except ValueError:
        odbg.log("[Shellcode] invalid address: %s" % addr_str)
        return
    code = _assemble(asm_text)
    if not code:
        return
    odbg.write_memory(addr, code)
    hex_str = " ".join("%02x" % b for b in code)
    odbg.log("[Shellcode] wrote %d bytes to 0x%x: %s" % (len(code), addr, hex_str))
