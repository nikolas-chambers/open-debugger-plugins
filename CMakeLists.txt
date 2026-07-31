cmake_minimum_required(VERSION 3.20)
project(open_debugger_plugins CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# General-purpose plugins for open-debugger (odbg) - nothing here is tied to
# any one target program.
#
# The SDK comes in as a submodule rather than by relative path, so this repo
# builds anywhere it is cloned. add_subdirectory defines odbg::plugin_sdk (the
# header) and add_odbg_plugin() (links odbg.lib, drops the DLL in the host's
# plugins folder); it deliberately does not build the SDK's own sample plugin.
#
# The host still has to be built first, for the same architecture - plugin
# DLLs load into odbg.exe's process and link its exports. Point at it with
# -DODBG_ROOT=<path to open-debugger> if it is not the sibling directory.

# Skipped when open-debugger is the one configuring us: it brings its own copy
# of the SDK in, and the targets are already defined by the time we get here.
if(NOT TARGET odbg::plugin_sdk)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/open-debugger-plugins_sdk/CMakeLists.txt")
        message(FATAL_ERROR
            "The plugin SDK submodule is empty. Run:\n"
            "  git submodule update --init --recursive")
    endif()
    add_subdirectory(external/open-debugger-plugins_sdk)
endif()

add_odbg_plugin(odbg-anti_anti)
