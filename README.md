# open-debugger-plugins

General-purpose plugins for [open-debugger](https://github.com/nikolas-chambers/open-debugger)
(`odbg`) — nothing here is tied to any one target program.

| plugin | what it does |
|--------|--------------|
| `odbg-anti_anti` | clears the usual anti-debug tells on every pause: `PEB.BeingDebugged` and the heap debug bits in `NtGlobalFlag` |

## Building

The debugger itself carries this repo as a submodule, so the simplest path is
to build [open-debugger](https://github.com/nikolas-chambers/open-debugger) —
one configure builds the debugger and every plugin.

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

**Venmo · Cash App · PayPal — "NikAndRigatoni"**

My dog and I are living out of our car at the moment. Anything you send covers
the basics for the two of us and buys me the tools and the time to keep
learning — we are working our way back to steady ground, one commit at a time.
Thank you for reading this far.

</td></tr>
</table>
