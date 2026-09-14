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

# ---------------------------------------------------------------------------
# odbg-python - embeds CPython and hosts Python plugins from a pyplugins/
# drop-folder (long-lived plugins) and scripts/ (one-shot scripts) next to the
# DLL. The interpreter the bridge embeds calls the exact same host Odbg_* API
# the native plugins get. Needs a CPython development package build-side; when
# it is absent this plugin is simply skipped so CI and SDK-only builds stay
# green.
# ---------------------------------------------------------------------------

find_package(Python3 COMPONENTS Interpreter Development.Embed)

if(Python3_FOUND)
    add_odbg_plugin(odbg-python)
    target_link_libraries(odbg-python PRIVATE Python3::Python)
    target_compile_definitions(odbg-python PRIVATE PY_SSIZE_T_CLEAN)

    # Ship the python_sdk package and the plugin/script drop-folders next to
    # the DLL, where the bridge looks for them; copy the examples in too so a
    # first run just works.
    get_target_property(_odbg_py_out odbg-python RUNTIME_OUTPUT_DIRECTORY)
    set(_odbg_py_dir "${CMAKE_CURRENT_SOURCE_DIR}/plugins/odbg-python")

    add_custom_command(TARGET odbg-python POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${_odbg_py_dir}/python_sdk"      "${_odbg_py_out}/python_sdk"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${_odbg_py_dir}/pyplugins"       "${_odbg_py_out}/pyplugins"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${_odbg_py_dir}/scripts"         "${_odbg_py_out}/scripts"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${_odbg_py_dir}/examples"        "${_odbg_py_out}/pyplugins"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${_odbg_py_dir}/examples_scripts" "${_odbg_py_out}/scripts")
else()
    message(WARNING "Python3 development package not found - building without odbg-python")
endif()
