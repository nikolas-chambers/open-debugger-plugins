"""Save and replay named action sequences (macros).

A macro is a named list of odbg.menu() labels that are executed in
order when the macro is invoked.  Macros are persisted via odbg.setting()
so they survive across sessions.
"""

import json
import odbg

NAME = "Hotkeys"


def plugininit(host_version):
    if host_version != odbg.ABI_VERSION:
        return 0
    odbg.register_command("macro: new", "create a macro (interactive)")
    odbg.register_command("macro: run", "run a macro by name")
    odbg.register_command("macro: list", "list saved macros")
    odbg.register_command("macro: delete", "delete a macro")
    odbg.log("[Hotkeys] ready — %d macros saved" % len(_load_macros()))
    return 1


def pluginmenu():
    macros = _load_macros()
    items = ["List macros"]
    for name in sorted(macros.keys()):
        items.append("Run: %s" % name)
    items.append("New macro (setting: macro.name + macro.actions)")
    items.append("Delete macro (setting: macro.del)")
    items.append("Help: macro format")
    return items


def pluginaction(action):
    macros = _load_macros()
    if action == 0:
        _list_macros(macros)
    elif 1 <= action < 1 + len(macros):
        names = sorted(macros.keys())
        _run_macro(names[action - 1], macros[names[action - 1]])
    elif action == 1 + len(macros):
        _new_macro()
    elif action == 2 + len(macros):
        _del_macro()
    elif action == 3 + len(macros):
        odbg.log("[Hotkeys] Macro format: set macro.name = 'MyMacro'")
        odbg.log("[Hotkeys] Set macro.actions = 'action1|action2|action3'")
        odbg.log("[Hotkeys] Actions are menu labels (partial match ok)")
        odbg.log("[Hotkeys] Example: macro.actions = 'Arm trace|Toggle chatty'")


def _load_macros():
    raw = odbg.get_setting("macros.json")
    if raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


def _save_macros(macros):
    odbg.set_setting("macros.json", json.dumps(macros))


def _list_macros(macros):
    if not macros:
        odbg.log("[Hotkeys] no macros saved")
        return
    odbg.log("[Hotkeys] saved macros:")
    for name, actions in sorted(macros.items()):
        odbg.log("[Hotkeys]   %s: %d actions" % (name, len(actions)))


def _new_macro():
    name = odbg.get_setting("macro.name") or ""
    actions_raw = odbg.get_setting("macro.actions") or ""
    if not name or not actions_raw:
        odbg.log("[Hotkeys] set macro.name and macro.actions first")
        return
    actions = [a.strip() for a in actions_raw.split("|") if a.strip()]
    if not actions:
        odbg.log("[Hotkeys] no actions in macro.actions")
        return
    macros = _load_macros()
    macros[name] = actions
    _save_macros(macros)
    odbg.log("[Hotkeys] macro '%s' saved (%d actions)" % (name, len(actions)))


def _del_macro():
    name = odbg.get_setting("macro.del") or ""
    if not name:
        odbg.log("[Hotkeys] set macro.del to the name to delete")
        return
    macros = _load_macros()
    if name in macros:
        del macros[name]
        _save_macros(macros)
        odbg.log("[Hotkeys] deleted macro '%s'" % name)
    else:
        odbg.log("[Hotkeys] no macro named '%s'" % name)


def _run_macro(name, actions):
    odbg.log("[Hotkeys] running macro '%s' (%d actions)..." % (name, len(actions)))
    labels = odbg._manager.menu() if hasattr(odbg, "_manager") else []
    for i, action_label in enumerate(actions):
        # partial match against the real menu
        found = False
        for j, label in enumerate(labels):
            if action_label.lower() in label.lower():
                odbg.log("[Hotkeys]   [%d] %s" % (i, label))
                try:
                    odbg._manager.invoke(j)
                except Exception as e:
                    odbg.log("[Hotkeys]   error: %s" % e)
                found = True
                break
        if not found:
            odbg.log("[Hotkeys]   [%d] '%s' — not in menu, skipping" % (i, action_label))
    odbg.log("[Hotkeys] macro '%s' done" % name)
