"""Plugin loader / dispatcher for the odbg-python bridge.

The native plugin is deliberately thin: it bootstraps this package, then its
menu/action/paused/close lifecycle exports become manager calls. All plugin
orchestration lives here in Python so it is easy to read, debug, and extend.

Python plugin contract (one ``*.py`` per plugin, dropped into ``pyplugins/``):

    NAME = "MyPlugin"                 # short name shown in the Plugins menu
    # optional:
    #   plugindata()            -> int   ABI version (default: odbg.ABI_VERSION)
    #   plugininit(hostVer)     -> int   return nonzero to stay loaded
    #   pluginmenu()            -> list[str]  <= ~24 chars each (menu caps at 32)
    #   pluginaction(actionNo)  -> None called when a menu item is picked
    #   paused(reason, regs)    -> None every stop; regs is odbg.Regs
    #   pluginclose()           -> None before the debugger exits

One-shot scripts (``*.py`` in the ``scripts/`` folder next to the DLL) are the
other mode: they are *not* loaded at startup, and get a "Run: <name>" menu
item that executes them on demand. Their contract is just a top-level
``def main(odbg)`` (or ``main()``) - ideal for disposable helpers like "snap
state" or "unpack to OEP".

Files starting with "_" are treated as private modules and never loaded as
plugins. A file that fails to import does not stop the others - its traceback
is logged and loading continues.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import traceback

import odbg as sdk

# Persistent namespace for the "py" command, so state survives between lines
# (define a helper on one line, call it on the next). `odbg` is the SDK.
_py_ns = {"odbg": sdk, "__name__": "__odbg_py__"}


class _PyPlugin:
    def __init__(self, name, module, menu_fn, action_fn, paused_fn, close_fn, init_fn):
        self.name = name
        self.module = module
        self.menu_fn = menu_fn
        self.action_fn = action_fn
        self.paused_fn = paused_fn
        self.close_fn = close_fn
        self.init_fn = init_fn
        self.items = []
        self.enabled = True   # toggled from the Plugins window / pyon-pyoff


_plugins: list[_PyPlugin] = []
_scripts: list = []   # [(label, path)] one-shot scripts from the scripts/ folder
_menu_map: list = []  # parallel to menu labels: an (entry,...) tuple per item

# Last directories seen, so reload() can re-discover without asking again.
_last_dirs = (None, None)


def _log_error(plugname, stage, exc):
    lines = traceback.format_exc().strip().splitlines()
    sdk.log("[python] %s %s: %s" % (plugname, stage, lines[-1] if lines else exc))
    for ln in lines[-4:-1]:
        sdk.log("[python]   " + ln.strip())


def discover(plugdir, scriptsdir):
    """(Re)load every plugin *.py in `plugdir` and list the one-shot scripts in
    `scriptsdir`. Safe to call multiple times; plugins are loaded eagerly, one-
    shot scripts are only executed when their menu item is picked."""
    global _plugins, _scripts, _last_dirs
    _last_dirs = (plugdir, scriptsdir)
    _plugins = []
    _scripts = []
    if not plugdir or not os.path.isdir(plugdir):
        return 0
    for fname in sorted(os.listdir(plugdir)):
        if fname.startswith("_") or not fname.endswith(".py"):
            continue
        stem = fname[:-3]
        path = os.path.join(plugdir, fname)
        try:
            plug = _load_one(stem, path)
        except Exception as exc:
            sdk.log("[python] failed to load %s: %s" % (fname, exc))
            _log_error(fname, "load", exc)
            continue
        if plug is not None:
            _plugins.append(plug)
            sdk.log("[python] loaded plugin %r from %s" % (plug.name, fname))
    if scriptsdir and os.path.isdir(scriptsdir):
        for fname in sorted(os.listdir(scriptsdir)):
            if fname.startswith("_") or not fname.endswith(".py"):
                continue
            _scripts.append((fname[:-3], os.path.join(scriptsdir, fname)))
    return len(_plugins)


def _load_one(stem, path):
    if stem in sys.modules:
        del sys.modules[stem]
    spec = importlib.util.spec_from_file_location(stem, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[stem] = mod
    spec.loader.exec_module(mod)

    # A .py with no plugin interface is a shared helper module (e.g. pe_utils),
    # not a plugin: importing it here (done above) makes it available for other
    # plugins to `import`, but it must not be registered as a plugin. Recognise a
    # real plugin by an explicit NAME or any lifecycle function.
    _iface = ("plugininit", "pluginmenu", "pluginaction", "paused", "pluginclose")
    if not hasattr(mod, "NAME") and not any(hasattr(mod, fn) for fn in _iface):
        return None

    name = getattr(mod, "NAME", None) or stem
    abi = getattr(mod, "plugindata", lambda: sdk.ABI_VERSION)()
    if abi != sdk.ABI_VERSION:
        sdk.log("[python] %s: ABI mismatch (want %s, got %s) - skipped"
                % (name, sdk.ABI_VERSION, abi))
        return None

    init = getattr(mod, "plugininit", None)
    if init is not None:
        ok = init(sdk.ABI_VERSION)
        if not ok:
            sdk.log("[python] %s: plugininit declined (host version %s)"
                    % (name, sdk.ABI_VERSION))
            return None

    return _PyPlugin(
        name=name,
        module=mod,
        menu_fn=getattr(mod, "pluginmenu", None),
        action_fn=getattr(mod, "pluginaction", None),
        paused_fn=getattr(mod, "paused", None),
        close_fn=getattr(mod, "pluginclose", None),
        init_fn=init,
    )


def menu():
    """Rebuild the flat Plugins-menu label list. Menu order:
    plugin items first, then one-shot script items, then "Reload scripts".
    Returns the labels and fills `_menu_map` so invoke(action) can route back
    to the right handler."""
    global _menu_map
    _menu_map = []
    labels = []
    # Enabled plugins contribute their own menu items.
    for i, plug in enumerate(_plugins):
        if not plug.enabled:
            continue
        items = list(plug.menu_fn()) if plug.menu_fn else []
        plug.items = items
        for j, label in enumerate(items):
            labels.append(label[:31])  # host item strings are 32 bytes
            _menu_map.append(("plugin", i, j))
    # One-shot scripts.
    for sname, spath in _scripts:
        labels.append(("Run: %s" % sname)[:31])
        _menu_map.append(("script", sname, spath))
    # Per-plugin enable/disable toggles (the script-manager controls).
    for i, plug in enumerate(_plugins):
        mark = "on" if plug.enabled else "off"
        labels.append(("[%s] %s" % (mark, plug.name))[:31])
        _menu_map.append(("toggle", i))
    if _plugins or _scripts:
        labels.append("Reload scripts")
        _menu_map.append(("reload", None))
    return labels


def invoke(action):
    """Run whatever the host menu item pointed at: a plugin action, a one-shot
    script's main(), or a reload. No-op on stale indices."""
    if not 0 <= action < len(_menu_map):
        return
    entry = _menu_map[action]
    try:
        if entry[0] == "plugin":
            _, i, j = entry
            plug = _plugins[i]
            if plug.action_fn:
                plug.action_fn(j)
        elif entry[0] == "script":
            _, name, path = entry
            _run_script(path, name)
        elif entry[0] == "toggle":
            _, i = entry
            _plugins[i].enabled = not _plugins[i].enabled
            sdk.log("[python] %s %s" % (_plugins[i].name,
                    "enabled" if _plugins[i].enabled else "disabled"))
        elif entry[0] == "reload":
            reload()
    except Exception as exc:
        _log_error("menu", "action", exc)


def _run_script(path, label):
    """Execute a one-shot script: import it fresh, call main(odbg) or main(),
    log any traceback. Never reloads a previously cached module - scripts are
    cheap and meant to be edited between uses."""
    spec = importlib.util.spec_from_file_location("_ody" + label.replace(" ", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
        main = getattr(mod, "main", None)
        if main is None:
            sdk.log("[python] script %r has no main()" % label)
            return
        try:
            main(sdk)
        except Exception as exc:
            _log_error(label, "script", exc)
    finally:
        sys.modules.pop(spec.name, None)


def paused(reason, regs_tuple):
    """Fan out a host stop event to every plugin's `paused` callback."""
    regs = sdk.Regs(*regs_tuple)
    for plug in list(_plugins):
        if not plug.enabled or not plug.paused_fn:
            continue
        try:
            plug.paused_fn(reason, regs)
        except Exception as exc:
            _log_error(plug.name, "paused", exc)


def close():
    """Shut Python plugins down before the interpreter is finalized."""
    for plug in list(_plugins):
        if plug.close_fn:
            try:
                plug.close_fn()
            except Exception as exc:
                _log_error(plug.name, "close", exc)
    _plugins.clear()
    _menu_map.clear()


def handle_command(cmdline):
    """Handle a command the host did not recognize. Owns 'py <code>' (run Python
    with the odbg SDK in scope, returning printed output / the expression repr)
    and 'pyrun <name>' (run a scripts/ file by name). Returns the reply string
    if claimed, or None to let the host try the next plugin / report unknown."""
    s = (cmdline or "").strip()
    if not s:
        return None
    parts = s.split(None, 1)
    verb = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""
    if verb == "py":
        return _run_py(arg)
    if verb == "pyrun":
        return _run_named_script(arg)
    if verb == "pyplugins":
        return _list_pyplugins()
    if verb in ("pyon", "pyoff"):
        return _toggle_plugin(arg, verb == "pyon")
    return None


def _list_pyplugins():
    rows = ["%-4s %s" % ("[on]" if p.enabled else "[off]", p.name) for p in _plugins]
    rows += ["[run] %s" % s for s, _ in _scripts]
    return "\n".join(rows) if rows else "(no python plugins or scripts)"


def _toggle_plugin(name, want_on):
    name = name.strip()
    for p in _plugins:
        if p.name.lower() == name.lower():
            p.enabled = want_on
            return "%s %s" % (p.name, "enabled" if want_on else "disabled")
    return "no such plugin: %s" % name


def _run_py(code):
    """Exec/eval one line of Python in the persistent namespace, capturing
    stdout. Tries eval first (so ``py 1+1`` echoes ``2``); falls back to exec
    for statements (``py x = read_u32(...)``)."""
    if not code.strip():
        return "usage: py <python code>   (odbg SDK in scope, e.g. py hex(odbg.get_reg('rip')))"
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            try:
                result = eval(compile(code, "<py>", "eval"), _py_ns)
                if result is not None:
                    print(repr(result))
            except SyntaxError:
                exec(compile(code, "<py>", "exec"), _py_ns)
    except Exception:
        line = traceback.format_exc().strip().splitlines()[-1]
        return "py error: " + line
    out = buf.getvalue().rstrip("\n")
    return out if out else "ok"


def _run_named_script(name):
    """Run a scripts/ file by name (with or without .py), like the menu item."""
    name = name.strip()
    if not name:
        return "usage: pyrun <script name>"
    stem = name[:-3] if name.endswith(".py") else name
    for sname, spath in _scripts:
        if sname == stem:
            _run_script(spath, sname)
            return "ran script %r" % sname
    return "no such script: %s (in scripts/)" % stem


def reload():
    """Drop all plugin modules (keeping user settings, which live in the host)
    and re-discover from the last-known plugin/script directories."""
    for plug in list(_plugins):
        sys.modules.pop(plug.module.__name__, None)
    _plugins.clear()
    _menu_map.clear()
    _scripts.clear()
    sdk.log("[python] reloading python plugins")
    discover(*_last_dirs)