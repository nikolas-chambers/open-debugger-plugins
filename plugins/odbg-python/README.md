# odbg-python

Embeds a **CPython** interpreter inside the debugger host and runs two kinds of
Python extension:

| mode | where | lifecycle |
|------|-------|-----------|
| **plugin** | `pyplugins/<name>.py` | long-lived: loaded once at init, receives every `menu()` / `paused()` / `invoke()` / `close()` call, can register settings |
| **script** | `scripts/<name>.py` | one-shot: started on demand from the menu with `main(odbg)` |

Both have full access to the same `Odbg_*` host API the native C plugins get,
exposed to Python through the bundled `odbg` package.

## Quick start

Build the host with a CPython development package (`Development.Embed`) in the
CMake configure step; `CMakeLists.txt` in this repo takes care of the rest and
ships `pyplugins/` + `scripts/` next to the DLL.

At runtime:

```
plugins/
├── odbg-python.dll
├── python_sdk/odbg/   ← the SDK package (ships with the build)
├── pyplugins/          ← drop your long-lived plugins here
│   ├── complete_plugin.py
│   ├── apilog.py
│   └── scan.py
└── scripts/            ← one-shot scripts
    └── snapshot.py
```

`Tools > Reload Plugins` rebuilds the Python-side catalogue without restarting
the host; a new file dropped into either folder shows up on the next reload.

## Reference plugins

### complete_plugin.py
Full-usage demo of every SDK surface: registers, memory, breakpoints, exec
control, settings, menu entry, `paused()` logic.

### apilog.py
Logs every host call with arguments; good starting point to understand which
calls your target is actually hitting. Starts **paused by default** (toggle in
settings) so it won't flood the output.

### scan.py
CE / ClawSearch-style memory scanner: step-by-step scan (unknown / greater /
smaller / equal to value, or exact / unknown pointer scan). Automatically
registers a menu command so it can be launched without leaving the UI.

## One-shot scripts

```python
# scripts/snapshot.py
def main(odbg):
    regs = odbg.get_regs()
    peb  = odbg.get_peb()
    odbg.log(f"RIP={regs.rip:#x}  PEB.BeingDebugged={peb}")
```

The script is executed on the GUI thread with full SDK access. Return
`"continue"` to automatically un-pause after the script finishes, or return
`None`/nothing to keep the debugger paused.

## Writing your own

Read the existing plugins for patterns. Key points:

- **File naming**: `pyplugins/my_plugin.py` (plugins must not start with `_`).
- **Contracts**: the loader calls `menu()` to build the menu, `invoke(action)` on
  click, `paused(reason, regs)` on every pause, `close()` on unload.
- **Thread safety**: every Python entry point is invoked with the GIL held and
  from a safe host thread; `Odbg_*` host calls are thread-safe per the SDK docs.
- **Errors**: exceptions inside `menu()`/`invoke()`/`paused()` are caught and
  logged; they never bring down other plugins or the host.
- **Settings**: use `odbg.setting()` / `odbg.setting = ...` to persist per-user
  state; the host stores them next to the executable.
- **Reload**: `Tools > Reload Plugins` wipes all Python plugins and re-discovers
  both folders; keep state in module-level variables or `odbg.setting` to survive
  reloads.

## Runtime requirements

The plugin embeds CPython, so at runtime it needs:

- **`python3xx.dll`** — the CMake build copies it next to `odbg.exe` automatically
  (from the Python it was configured against).
- **The Python standard library** — CPython locates this at `Py_Initialize`. On a
  machine with a matching Python installed and on `PATH`/registry this just
  works. For a self-contained distribution, ship the official *embeddable*
  Python package (its `pythonXX.zip` stdlib) next to `odbg.exe`, or set
  `PYTHONHOME`.

Built only when CMake finds a Python with the `Development.Embed` component;
otherwise the plugin is skipped and the rest of the build is unaffected.
