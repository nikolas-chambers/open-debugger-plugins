// odbg-python - an odbg plugin that runs Python plugins.
//
// Classical Olly-style plugin architecture has two parts:
//   1. the host (odbg.exe) exports a flat C API the plugin links against;
//   2. the plugin DLL exports lifecycle hooks the host resolves by name.
//
// This plugin does exactly that, then turns the whole host API over to a
// Python interpreter it embeds (CPython). Its lifecycle exports hand off to a
// pure-Python plugin manager (plugins/python_sdk/odbg/_manager.py), and it
// grows a per-plugin menu, action dispatch, a paused fan-out, and settings +
// command registration - the full odbg_plugin_sdk surface, exposed to Python.
//
// A Python plugin is just a .py file dropped into the `pyplugins/` folder next
// to this DLL (see ../examples/ for reference plugins). Runtime pickup:
//   * whatever the host asks for, files starting with `_` are never loaded
//   * a failing .py file logs a traceback and does not stop the others
//   * "Reload scripts" in the Plugins menu re-discovers the folder
//
// Threading model (important): the host calls Odbg_Pluginaction on its UI
// thread and Odbg_Paused on its engine worker thread. Python requires the GIL
// on whichever thread enters it, so every Python entry point here attaches
// with PyGILState_Ensure/Release. Py_Initialize (in Plugininit) and
// Py_FinalizeEx (in Pluginclose) both run on the host's plugin life-cycle
// thread, as shown. All Odbg_* host calls used below are themselves marshaled
// onto the engine worker by the host, so callers never touch that thread.

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "odbg_plugin_sdk.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
// Plugin-wide state
// ---------------------------------------------------------------------------

static PyObject* g_manager = nullptr;     // odbg._manager module
static std::wstring g_pydir;              // <dll dir>\pyplugins  (long-lived plugins)
static std::wstring g_scriptsdir;         // <dll dir>\scripts    (one-shot scripts)

class Gil {
    PyGILState_STATE state_;
public:
    Gil() : state_(PyGILState_Ensure()) {}
    ~Gil() { PyGILState_Release(state_); }
};

static std::wstring Utf8ToWide(const char* s) {
    if (!s) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
    return w;
}

static std::string WideToUtf8(const wchar_t* s) {
    if (!s) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    std::string a(n > 0 ? n - 1 : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, s, -1, &a[0], n, nullptr, nullptr);
    return a;
}

static std::wstring ModuleDir() {
    HMODULE h = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)(void*)&Odbg_Plugindata, &h))
        return L".";
    wchar_t path[1024];
    DWORD n = GetModuleFileNameW(h, path, 1024);
    if (n == 0) return L".";
    std::wstring full(path, n);
    size_t slash = full.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : full.substr(0, slash);
}

// Copy an item label into the host's 32-byte field, truncating on a UTF-8
// character boundary so a multibyte sequence is never split.
static void CopyShort(char dst[32], const char* utf8, size_t cap) {
    size_t n = strlen(utf8);
    if (n >= cap) n = cap - 1;
    memcpy(dst, utf8, n);
    dst[n] = 0;
    while (n > 0 && ((unsigned char)dst[n - 1] & 0xC0) == 0x80) --n;
    dst[n] = 0;
}

// ---------------------------------------------------------------------------
// Python bootstrapping
// ---------------------------------------------------------------------------

static const char kBootStrap[] =
    "import _odbg\n"
    "import sys, os\n"
    "pydir = _odbg.plugin_dir\n"
    "for d in (os.path.join(pydir, 'python_sdk'), os.path.join(pydir, 'pyplugins')):\n"
    "    if os.path.isdir(d) and d not in sys.path:\n"
    "        sys.path.insert(0, d)\n"
    "__import__('odbg')\n";

static void CallNoArg(const char* method) {
    if (!g_manager) return;
    Gil gil;
    PyObject* r = PyObject_CallMethod(g_manager, method, nullptr);
    if (!r) PyErr_Print();
    else Py_DECREF(r);
}

static void DiscoverPlugins() {
    if (!g_manager) return;
    Gil gil;
    std::string pd = WideToUtf8(g_pydir.c_str());
    std::string sd = WideToUtf8(g_scriptsdir.c_str());
    if (pd.empty()) pd = ".";
    if (sd.empty()) sd = ".";
    PyObject* r = PyObject_CallMethod(g_manager, "discover", "ss", pd.c_str(), sd.c_str());
    if (!r) PyErr_Print();
    else Py_DECREF(r);
}

// ---------------------------------------------------------------------------
// The `_odbg` builtin - raw, untyped host-API surface for Python.
// ergonomic wrappers live in python_sdk/odbg/__init__.py.
// ---------------------------------------------------------------------------

static PyObject* m_command(PyObject*, PyObject* args) {
    const char* cmd;
    if (!PyArg_ParseTuple(args, "s", &cmd)) return nullptr;
    char out[8192];
    int n = Odbg_Command(cmd, out, (int)sizeof(out));
    if (n < 0) Py_RETURN_NONE;
    return Py_BuildValue("y#", out, n);
}

static PyObject* m_log(PyObject*, PyObject* args) {
    const char* text;
    if (!PyArg_ParseTuple(args, "s", &text)) return nullptr;
    Odbg_Log(text);
    Py_RETURN_NONE;
}

static PyObject* m_register_command(PyObject*, PyObject* args) {
    const char* name, * help_;
    if (!PyArg_ParseTuple(args, "ss", &name, &help_)) return nullptr;
    Odbg_RegisterCommand(name, help_);
    Py_RETURN_NONE;
}

static PyObject* m_session_active(PyObject*, PyObject*) {
    return PyBool_FromLong(Odbg_SessionActive() ? 1 : 0);
}

static PyObject* m_stopped(PyObject*, PyObject*) {
    return PyBool_FromLong(Odbg_Stopped() ? 1 : 0);
}

static PyObject* m_read_memory(PyObject*, PyObject* args) {
    unsigned long long addr;
    int size;
    if (!PyArg_ParseTuple(args, "Ki", &addr, &size)) return nullptr;
    if (size < 0) { PyErr_SetString(PyExc_ValueError, "negative size"); return nullptr; }
    std::string buf(size > 0 ? size : 0, '\0');
    if (size > 0 && !Odbg_Readmemory(addr, buf.data(), (unsigned long)size))
        Py_RETURN_NONE;
    return PyBytes_FromStringAndSize(buf.data(), size);
}

static PyObject* m_write_memory(PyObject*, PyObject* args) {
    unsigned long long addr;
    const char* data;
    Py_ssize_t len;
    if (!PyArg_ParseTuple(args, "Ky#", &addr, &data, &len)) return nullptr;
    return PyBool_FromLong(Odbg_Writememory(addr, data, (unsigned long)len) ? 1 : 0);
}

static PyObject* m_get_reg(PyObject*, PyObject* args) {
    const char* name;
    if (!PyArg_ParseTuple(args, "s", &name)) return nullptr;
    std::wstring w = Utf8ToWide(name);
    return PyLong_FromUnsignedLongLong(Odbg_Getreg(w.c_str()));
}

static PyObject* m_set_reg(PyObject*, PyObject* args) {
    const char* name;
    unsigned long long value;
    if (!PyArg_ParseTuple(args, "sK", &name, &value)) return nullptr;
    std::wstring w = Utf8ToWide(name);
    return PyBool_FromLong(Odbg_Setreg(w.c_str(), value) ? 1 : 0);
}

static PyObject* m_get_regs(PyObject*, PyObject*) {
    OdbgRegs r{};
    Odbg_Getregs(&r);
    return Py_BuildValue("(KKKKKKKKKKKKK)",
        (unsigned long long)r.rax, (unsigned long long)r.rbx,
        (unsigned long long)r.rcx, (unsigned long long)r.rdx,
        (unsigned long long)r.rsi, (unsigned long long)r.rdi,
        (unsigned long long)r.rbp, (unsigned long long)r.rsp,
        (unsigned long long)r.rip, (unsigned long long)r.r8,
        (unsigned long long)r.r9, (unsigned long long)r.r10,
        (unsigned long long)r.r11);
}

static PyObject* m_add_breakpoint(PyObject*, PyObject* args) {
    const char* spec;
    if (!PyArg_ParseTuple(args, "s", &spec)) return nullptr;
    std::wstring w = Utf8ToWide(spec);
    return PyLong_FromLong(Odbg_Addbreakpoint(w.c_str()));
}

static PyObject* m_remove_breakpoint(PyObject*, PyObject* args) {
    int id;
    if (!PyArg_ParseTuple(args, "i", &id)) return nullptr;
    return PyBool_FromLong(Odbg_Removebreakpoint(id) ? 1 : 0);
}

static PyObject* m_get_peb(PyObject*, PyObject*) {
    return PyLong_FromUnsignedLongLong(Odbg_Getpeb());
}

static PyObject* m_go(PyObject*, PyObject*) { Odbg_Go(); Py_RETURN_NONE; }
static PyObject* m_pause(PyObject*, PyObject*) { Odbg_Pause(); Py_RETURN_NONE; }
static PyObject* m_step_into(PyObject*, PyObject*) { Odbg_Stepinto(); Py_RETURN_NONE; }
static PyObject* m_step_over(PyObject*, PyObject*) { Odbg_Stepover(); Py_RETURN_NONE; }

static PyObject* m_set_setting(PyObject*, PyObject* args) {
    const char* key, * value;
    if (!PyArg_ParseTuple(args, "ss", &key, &value)) return nullptr;
    Odbg_Setsetting(key, value);
    Py_RETURN_NONE;
}

static PyObject* m_get_setting(PyObject*, PyObject* args) {
    const char* key;
    if (!PyArg_ParseTuple(args, "s", &key)) return nullptr;
    char out[8192];
    int n = Odbg_Getsetting(key, out, (int)sizeof(out));
    if (n < 0) Py_RETURN_NONE;
    return Py_BuildValue("y#", out, n);
}

static PyMethodDef kMethods[] = {
    {"command",          m_command,          METH_VARARGS,
     "command(cmd) -> bytes|None - run any odbg verb, return its reply"},
    {"log",              m_log,              METH_VARARGS, "log(text) - append to the GUI Log pane"},
    {"register_command", m_register_command, METH_VARARGS, "register_command(name, help)"},
    {"session_active",   m_session_active,   METH_NOARGS,  "session_active() -> bool"},
    {"stopped",          m_stopped,          METH_NOARGS,  "stopped() -> bool"},
    {"read_memory",      m_read_memory,      METH_VARARGS, "read_memory(addr, size) -> bytes|None"},
    {"write_memory",     m_write_memory,     METH_VARARGS, "write_memory(addr, data) -> bool"},
    {"get_reg",          m_get_reg,          METH_VARARGS, "get_reg(name) -> int"},
    {"set_reg",          m_set_reg,          METH_VARARGS, "set_reg(name, value) -> bool"},
    {"get_regs",         m_get_regs,         METH_NOARGS,  "get_regs() -> (rax..r11)"},
    {"add_breakpoint",   m_add_breakpoint,   METH_VARARGS, "add_breakpoint(spec) -> id"},
    {"remove_breakpoint", m_remove_breakpoint, METH_VARARGS, "remove_breakpoint(id) -> bool"},
    {"get_peb",          m_get_peb,          METH_NOARGS,  "get_peb() -> int"},
    {"go",               m_go,               METH_NOARGS,  "go()"},
    {"pause",            m_pause,            METH_NOARGS,  "pause()"},
    {"step_into",        m_step_into,        METH_NOARGS,  "step_into()"},
    {"step_over",        m_step_over,        METH_NOARGS,  "step_over()"},
    {"set_setting",      m_set_setting,      METH_VARARGS, "set_setting(key, value)"},
    {"get_setting",      m_get_setting,      METH_VARARGS, "get_setting(key) -> bytes|None"},
    {nullptr, nullptr, 0, nullptr}
};

static PyModuleDef kModule = {
    PyModuleDef_HEAD_INIT, "_odbg", PyDoc_STR("odbg host-API builtin (raw layer)"), -1, kMethods
};

PyMODINIT_FUNC PyInit__odbg(void) {
    std::wstring dir = ModuleDir();
    std::string dir8 = WideToUtf8(dir.c_str());
    std::string sdk8 = WideToUtf8((dir + L"\\python_sdk").c_str());
    std::string plug8 = WideToUtf8((dir + L"\\pyplugins").c_str());

    PyObject* m = PyModule_Create(&kModule);
    if (!m) return nullptr;
    if (PyModule_AddIntConstant(m, "ABI_VERSION", ODBG_PLUGIN_ABI_VERSION) < 0 ||
        PyModule_AddIntConstant(m, "ORIGIN_PLUGINS_MENU", ODBG_ORIGIN_PLUGINS_MENU) < 0 ||
        PyModule_AddIntConstant(m, "PAUSE_BREAKPOINT", ODBG_PAUSE_BREAKPOINT) < 0 ||
        PyModule_AddIntConstant(m, "PAUSE_STEP", ODBG_PAUSE_STEP) < 0 ||
        PyModule_AddIntConstant(m, "PAUSE_ATTACH_OR_LAUNCH", ODBG_PAUSE_ATTACH_OR_LAUNCH) < 0 ||
        PyModule_AddStringConstant(m, "plugin_dir", dir8.c_str()) < 0 ||
        PyModule_AddStringConstant(m, "sdk_dir", sdk8.c_str()) < 0 ||
        PyModule_AddStringConstant(m, "plugdir", plug8.c_str()) < 0) {
        Py_DECREF(m);
        return nullptr;
    }
    return m;
}

// ---------------------------------------------------------------------------
// Lifecycle exports (resolved by the host by name)
// ---------------------------------------------------------------------------

extern "C" __declspec(dllexport) int Odbg_Plugindata(char shortname[32]) {
    strcpy_s(shortname, 32, "Python");
    return ODBG_PLUGIN_ABI_VERSION;
}

extern "C" __declspec(dllexport) int Odbg_Plugininit(int hostVersion) {
    if (hostVersion != ODBG_PLUGIN_ABI_VERSION) return 0;

    g_pydir = ModuleDir() + L"\\pyplugins";
    g_scriptsdir = ModuleDir() + L"\\scripts";

    // Must happen before Py_Initialize. The builtin reads its dir from here,
    // so the dir strings live on and are visible from Python.
    if (PyImport_AppendInittab("_odbg", PyInit__odbg) < 0) {
        Odbg_Log("[odbg-python] PyImport_AppendInittab failed");
        return 0;
    }

    Py_Initialize();
    if (!Py_IsInitialized()) {
        Odbg_Log("[odbg-python] Py_Initialize failed");
        return 0;
    }

    {
        Gil gil;
        if (PyRun_SimpleString(kBootStrap) != 0) {
            PyErr_Print();
            Py_FinalizeEx();
            return 0;
        }
        g_manager = PyImport_ImportModule("odbg._manager");
        if (!g_manager) {
            PyErr_Print();
            Py_FinalizeEx();
            return 0;
        }
    }

    Odbg_RegisterCommand("python: reload scripts",
        "Re-load every plugin .py from the pyplugins/ folder next to odbg-python.dll");
    char buf[128];
    snprintf(buf, sizeof(buf), "[odbg-python] embedded Python %s", PY_VERSION);
    Odbg_Log(buf);
    Odbg_Log("[odbg-python] python plugins: pyplugins/ (long-lived) + scripts/ (one-shot), next to this DLL");

    DiscoverPlugins();
    Odbg_Log("[odbg-python] ready - 'Reload scripts' re-reads pyplugins/");
    return 1;
}

extern "C" __declspec(dllexport) int Odbg_Pluginmenu(int /*origin*/, char items[][32], int maxItems) {
    if (!g_manager) return 0;
    Gil gil;
    PyObject* m = PyObject_CallMethod(g_manager, "menu", nullptr);
    if (!m) { PyErr_Print(); return 0; }
    Py_ssize_t count = PyList_Size(m);
    if (count > maxItems) count = maxItems;
    int n = 0;
    for (Py_ssize_t i = 0; i < count; ++i) {
        PyObject* item = PyList_GetItem(m, i);
        const char* s = item ? PyUnicode_AsUTF8(item) : nullptr;
        if (!s) { PyErr_Clear(); continue; }
        CopyShort(items[n], s, 32);
        ++n;
    }
    Py_DECREF(m);
    return n;
}

extern "C" __declspec(dllexport) void Odbg_Pluginaction(int /*origin*/, int action) {
    if (!g_manager || action < 0) return;
    Gil gil;
    PyObject* r = PyObject_CallMethod(g_manager, "invoke", "i", action);
    if (!r) PyErr_Print();
    else Py_DECREF(r);
}

extern "C" __declspec(dllexport) void Odbg_Paused(int reason, const OdbgRegs* regs) {
    if (!g_manager || !regs) return;
    Gil gil;
    PyObject* t = Py_BuildValue("(KKKKKKKKKKKKK)",
        (unsigned long long)regs->rax, (unsigned long long)regs->rbx,
        (unsigned long long)regs->rcx, (unsigned long long)regs->rdx,
        (unsigned long long)regs->rsi, (unsigned long long)regs->rdi,
        (unsigned long long)regs->rbp, (unsigned long long)regs->rsp,
        (unsigned long long)regs->rip, (unsigned long long)regs->r8,
        (unsigned long long)regs->r9, (unsigned long long)regs->r10,
        (unsigned long long)regs->r11);
    if (!t) { PyErr_Print(); return; }
    PyObject* r = PyObject_CallMethod(g_manager, "paused", "KO", reason, t);
    Py_DECREF(t);
    if (!r) PyErr_Print();
    else Py_DECREF(r);
}

extern "C" __declspec(dllexport) void Odbg_Pluginclose(void) {
    if (g_manager) {
        CallNoArg("close");
        Gil gil;
        Py_DECREF(g_manager);
        g_manager = nullptr;
    }
    Py_FinalizeEx();
}