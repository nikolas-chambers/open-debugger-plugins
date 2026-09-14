"""decompile - a Ghidra-powered decompiler for odbg.

The "shell out to a great free tool" pattern (vs emulate.py's pip-library
pattern): drives Ghidra's headless analyzer to decompile the function under the
cursor and shows the pseudo-C. We don't write a decompiler - we conduct Ghidra
(Apache-2.0, the best free one).

    decompile [addr]    decompile the function containing addr (default RIP)

How it works: Ghidra imports the module's on-disk image once into a cached
project, then a post-script (ghidra_scripts/odbg_decompile.py) decompiles the
function at the target RVA and writes the C to a temp file we read back.

Setup (one-time), via odbg settings or auto-detect:
    ghidra_home   folder of a Ghidra install (has support/analyzeHeadless.bat)
    ghidra_java   a JDK 21 home (Ghidra 11+/12 needs 21); if unset, Ghidra's
                  own launcher search is used
Set them from the command bar with:  py odbg.set_setting('ghidra_home', r'C:\\ghidra')
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile

import odbg

NAME = "Decompile"

_SCRIPT_DIRNAME = "ghidra_scripts"          # ships next to this plugin
_TEMPLATE = "odbg_decompile.java"           # the shipped Java post-script
_RUNTIME_CLASS = "OdbgDecompile"            # controlled class name we stage under
_PROJECTS = os.path.join(tempfile.gettempdir(), "odbg_ghidra_projects")
_STAGING = os.path.join(tempfile.gettempdir(), "odbg_ghidra_scripts")


def plugininit(host_version):
    odbg.register_verb("decompile", _decompile_cmd)
    odbg.register_command("decompile [addr]",
                          "Decompile the function at addr/RIP with Ghidra (headless)")
    home = _ghidra_home()
    odbg.log("[decompile] " + ("Ghidra: %s" % home if home
             else "Ghidra not found - set it: py odbg.set_setting('ghidra_home', r'C:\\\\path\\\\to\\\\ghidra')"))
    return 1


def pluginmenu():
    return ["Decompile function at RIP"]


def pluginaction(action):
    if action == 0:
        odbg.log("[decompile] " + _decompile_cmd(""))


# ---------------------------------------------------------------------------

def _ghidra_home():
    h = odbg.get_setting("ghidra_home")
    if h and os.path.isdir(h):
        return h
    # Auto-detect a common install.
    for pat in (r"C:\PROGRAMS\ghidra_*_PUBLIC", r"C:\ghidra_*_PUBLIC",
                r"C:\ghidra*", r"C:\Program Files\ghidra*"):
        hits = sorted(glob.glob(pat))
        for c in hits:
            if os.path.isfile(os.path.join(c, "support", "analyzeHeadless.bat")):
                return c
    return ""


def _headless(home):
    return os.path.join(home, "support", "analyzeHeadless.bat")


def _stage_script():
    """Copy the shipped Java post-script into a dedicated, wiped dir under a
    class name we own, and return (dir, script_filename).

    Ghidra keys its global ScriptInfo registry by simple script *name*.  If the
    same script name is registered from two directories (e.g. a source checkout
    plus an installed copy), the wrong one wins and the OSGi bundle load fails
    with "Failed to find source bundle containing script".  Staging into one
    dedicated dir under a name we control makes that collision impossible and
    self-heals a machine that was previously polluted.
    """
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       _SCRIPT_DIRNAME, _TEMPLATE)
    with open(src, encoding="utf-8") as f:
        code = f.read().replace("class odbg_decompile ",
                                "class %s " % _RUNTIME_CLASS)
    shutil.rmtree(_STAGING, ignore_errors=True)
    os.makedirs(_STAGING, exist_ok=True)
    name = _RUNTIME_CLASS + ".java"
    with open(os.path.join(_STAGING, name), "w", encoding="utf-8") as f:
        f.write(code)
    return _STAGING, name


def _module_for(addr):
    """Return (base, on-disk path) of the module containing addr, or (0, '')."""
    try:
        import pe_utils
        pe_utils.refresh_modules()   # a new stop may be a new process (ASLR)
        for base, end, name in pe_utils.modules():
            if base <= addr < end:
                return base, name
    except Exception as e:
        odbg.log("[decompile] module lookup failed: %s" % e)
    return 0, ""


def _decompile_cmd(arg):
    if not odbg.session_active() or not odbg.stopped():
        return "decompile needs a stopped target"
    home = _ghidra_home()
    if not home:
        return "Ghidra not found - set: py odbg.set_setting('ghidra_home', r'C:\\path\\to\\ghidra')"

    try:
        target = int(arg.strip(), 0) if arg.strip() else odbg.get_reg("rip")
    except ValueError:
        target = odbg.get_reg("rip")

    base, path = _module_for(target)
    if not base or not os.path.isfile(path):
        return "no on-disk module for %#x (path: %r)" % (target, path)
    rva = target - base

    os.makedirs(_PROJECTS, exist_ok=True)
    proj_name = os.path.splitext(os.path.basename(path))[0]
    rep = os.path.join(_PROJECTS, proj_name + ".rep")   # Ghidra project marker
    outfile = os.path.join(tempfile.gettempdir(), "odbg_decompiled.c")
    try:
        os.remove(outfile)
    except OSError:
        pass

    script_dir, script_name = _stage_script()
    cmd = [_headless(home), _PROJECTS, proj_name,
           "-scriptPath", script_dir,
           "-postScript", script_name, "%#x" % rva, outfile]
    # Import (+ analyze) the first time; reuse the cached project afterwards.
    if os.path.isdir(rep):
        cmd += ["-process", os.path.basename(path), "-noanalysis"]
    else:
        cmd += ["-import", path]

    env = dict(os.environ)
    jdk = odbg.get_setting("ghidra_java")
    if jdk and os.path.isdir(jdk):
        env["JAVA_HOME"] = jdk

    odbg.log("[decompile] running Ghidra (first call analyzes the module - this can take a while)...")
    try:
        subprocess.run(cmd, env=env, cwd=home, timeout=600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return "Ghidra timed out"
    except Exception as e:
        return "Ghidra failed to launch: %s" % e

    if not os.path.isfile(outfile):
        return "decompile produced no output (JDK 21 configured? see ghidra_java setting)"
    c = open(outfile, encoding="utf-8", errors="replace").read().strip()
    for line in c.splitlines():
        odbg.log("  " + line)
    return "decompiled %s+%#x (%d lines)" % (proj_name, rva, len(c.splitlines()))
