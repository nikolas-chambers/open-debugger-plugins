# open-debugger-plugins

General-purpose plugins for [open-debugger](https://github.com/nikolas-chambers/open-debugger)
(`odbg`) — nothing here is tied to any one target program.

| plugin | what it does |
|--------|--------------|
| `odbg-anti_anti` | clears the usual anti-debug tells on every pause: `PEB.BeingDebugged` and the heap debug bits in `NtGlobalFlag` |
| `odbg-python` | embeds a CPython interpreter and runs **Python plugins** from a `pyplugins/` drop-folder (long-lived: menu/paused/settings) and one-shot **scripts** from `scripts/` (a `main(odbg)` run on demand). Ships the full `Odbg_*` SDK to Python (`odbg.command()`, memory, registers, breakpoints) plus reference plugins: `complete_plugin.py` (full SDK demo), `apilog.py` (API-call logger), `scan.py` (CE/ClawSearch-style memory scanner), `snapshot.py` (one-shot script). See `plugins/odbg-python/README.md`. |

## Building

The debugger itself carries this repo as a submodule, so the simplest path is
to build [open-debugger](https://github.com/nikolas-chambers/open-debugger) —
one configure builds the debugger and every plugin. `odbg-python` additionally
needs a CPython development package (the `Development.Embed` component); if it
is not found the plugin is skipped with a warning, so SDK-only builds still
work.

To build this repo on its own, against an already-built debugger next door:

```
git clone --recurse-submodules https://github.com/nikolas-chambers/open-debugger-plugins
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The DLL lands in `../open-debugger/build/Release/plugins`, where `odbg.exe`
picks it up at startup. Point elsewhere with `-DODBG_ROOT=<path>`. The
architecture has to match the host — a plugin DLL is loaded into `odbg.exe`'s
own process.

## Writing your own

Add a folder under `plugins/`, one `.cpp` named after it, and a line in
`CMakeLists.txt`. The API, the rules, and a fully worked example live in
[open-debugger-plugins_sdk](https://github.com/nikolas-chambers/open-debugger-plugins_sdk),
which comes in here as a submodule.

---

<table>
<tr><td>

### ☕ Buy me a coffee?

**Venmo · Cash App · PayPal — "NikAndRigatoni" (Nikolas Chambers)**

The honest version: my dog and I are living in the car right now. I spend my
days writing code anyway - bringing old projects of mine back to life one at a
time, and learning everything I can along the way. If anything here was useful
to you, a few bucks goes to dog food, gas, and keeping the laptop running, and
it buys me more hours to keep building. Either way, thanks for reading this far.

</td></tr>
</table>
