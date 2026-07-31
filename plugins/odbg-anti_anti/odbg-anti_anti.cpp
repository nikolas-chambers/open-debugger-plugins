// antianti - a first, deliberately small anti-anti-debug plugin for odbg.
//
// On every pause, clears the two classic, offset-stable anti-debug tells in
// the debuggee's PEB:
//   - PEB.BeingDebugged (offset 0x02 on x64)   -> what IsDebuggerPresent() reads
//   - PEB.NtGlobalFlag  (offset 0xBC on x64)   -> heap debug-check bits that
//     give away a debugger even when BeingDebugged has been cleared
//
// Deliberately does NOT touch heap Flags/ForceFlags structures - those moved
// around across Windows heap implementations (classic heap vs segment heap)
// and guessing wrong there means corrupting the debuggee's heap state, not
// just failing to hide.

#include "odbg_plugin_sdk.h"

#include <cstdio>
#include <cstring>

static bool g_enabled = true;
static bool g_clearedBeingDebugged = false;
static bool g_clearedNtGlobalFlag = false;

constexpr unsigned long long kPebBeingDebuggedOffset = 0x02;
constexpr unsigned long long kPebNtGlobalFlagOffset = 0xBC;
constexpr unsigned long kHeapDebugBits = 0x70; // FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS

extern "C" __declspec(dllexport) int Odbg_Plugindata(char shortname[32]) {
    strcpy_s(shortname, 32, "AntiAntiDebug");
    return ODBG_PLUGIN_ABI_VERSION;
}

extern "C" __declspec(dllexport) int Odbg_Plugininit(int hostVersion) {
    if (hostVersion != ODBG_PLUGIN_ABI_VERSION) return 0;
    // Advertise what this plugin does in the Command Reference window
    // (Command pane "?" > Plugin commands). These are driven from the plugin's
    // Plugins menu (Enable/Disable); listing them here just documents them.
    Odbg_RegisterCommand("antianti: Enable",
        "Clear anti-debug tells (PEB.BeingDebugged, NtGlobalFlag) on every pause");
    Odbg_RegisterCommand("antianti: Disable",
        "Stop clearing anti-debug tells - leave the PEB untouched");
    return 1;
}

extern "C" __declspec(dllexport) int Odbg_Pluginmenu(int /*origin*/, char items[][32], int maxItems) {
    int n = 0;
    if (n < maxItems) strcpy_s(items[n++], 32, "Enable");
    if (n < maxItems) strcpy_s(items[n++], 32, "Disable");
    return n;
}

extern "C" __declspec(dllexport) void Odbg_Pluginaction(int /*origin*/, int action) {
    if (action == 0) { g_enabled = true; Odbg_Log("[antianti] enabled"); }
    else if (action == 1) { g_enabled = false; Odbg_Log("[antianti] disabled"); }
}

extern "C" __declspec(dllexport) void Odbg_Paused(int /*reason*/, const OdbgRegs* /*regs*/) {
    if (!g_enabled) return;
    unsigned long long peb = Odbg_Getpeb();
    if (!peb) return;

    unsigned char beingDebugged = 0;
    if (Odbg_Readmemory(peb + kPebBeingDebuggedOffset, &beingDebugged, 1) && beingDebugged != 0) {
        unsigned char zero = 0;
        if (Odbg_Writememory(peb + kPebBeingDebuggedOffset, &zero, 1) && !g_clearedBeingDebugged) {
            g_clearedBeingDebugged = true;
            Odbg_Log("[antianti] cleared PEB.BeingDebugged");
        }
    }

    unsigned long ntGlobalFlag = 0;
    if (Odbg_Readmemory(peb + kPebNtGlobalFlagOffset, &ntGlobalFlag, sizeof(ntGlobalFlag)) &&
        (ntGlobalFlag & kHeapDebugBits) != 0) {
        unsigned long cleared = ntGlobalFlag & ~kHeapDebugBits;
        if (Odbg_Writememory(peb + kPebNtGlobalFlagOffset, &cleared, sizeof(cleared)) && !g_clearedNtGlobalFlag) {
            g_clearedNtGlobalFlag = true;
            char buf[96];
            sprintf_s(buf, "[antianti] cleared PEB.NtGlobalFlag heap-debug bits (0x%lx -> 0x%lx)", ntGlobalFlag, cleared);
            Odbg_Log(buf);
        }
    }
}

extern "C" __declspec(dllexport) void Odbg_Pluginclose(void) {
}
