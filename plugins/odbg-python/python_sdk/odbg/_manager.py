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

import importlib.util
import os
import sys
import traceback

import odbg as sdk


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
    for i, plug in enumerate(_plugins):
        items = list(plug.menu_fn()) if plug.menu_fn else []
        plug.items = items
        for j, label in enumerate(items):
            labels.append(label[:31])  # host item strings are 32 bytes
            _menu_map.append(("plugin", i, j))
    for sname, spath in _scripts:
        labels.append(("Run: %s" % sname)[:31])
        _menu_map.append(("script", sname, spath))
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
        if not plug.paused_fn:
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