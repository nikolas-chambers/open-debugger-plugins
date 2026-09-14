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

# --- odbg-python: embeds CPython so plugins/scripts can be written in Python ---
#
# Optional: only built when a CPython development package with the embed
# component is found (configure with a Python that has Development.Embed - the
# standard python.org installer includes it). If it is missing, the plugin is
# skipped and the rest of the build is unaffected. When built, the Python SDK
# package and the example pyplugins/ + scripts/ are shipped next to the DLL.
find_package(Python3 QUIET COMPONENTS Development.Embed)
if(Python3_FOUND)
    add_odbg_plugin(odbg-python)
    target_include_directories(odbg-python PRIVATE ${Python3_INCLUDE_DIRS})
    target_link_libraries(odbg-python PRIVATE ${Python3_LIBRARIES})

    # Ship the Python side next to the DLL: python_sdk/ (the odbg package),
    # pyplugins/ (long-lived plugins) and scripts/ (one-shot). The DLL's output
    # dir is the host's plugins folder; the plugin resolves these relative to it.
    set(_pysrc "${CMAKE_CURRENT_SOURCE_DIR}/plugins/odbg-python")
    add_custom_command(TARGET odbg-python POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${_pysrc}/python_sdk" "$<TARGET_FILE_DIR:odbg-python>/python_sdk"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${_pysrc}/pyplugins" "$<TARGET_FILE_DIR:odbg-python>/pyplugins"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${_pysrc}/scripts" "$<TARGET_FILE_DIR:odbg-python>/scripts"
        COMMENT "odbg-python: staging python_sdk/, pyplugins/, scripts/")

    # The embedded interpreter needs python3xx.dll at load time, resolved next
    # to odbg.exe (the plugin DLL's grandparent dir). Copy the runtime DLLs
    # there so the plugin loads without Python having to be on PATH. (The Python
    # standard library still has to be reachable - an installed Python on PATH,
    # or bundle the embeddable distribution; see the plugin README.)
    file(GLOB _pyrtdlls "${Python3_RUNTIME_LIBRARY_DIRS}/python3*.dll")
    foreach(_dll ${_pyrtdlls})
        add_custom_command(TARGET odbg-python POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_dll}" "$<TARGET_FILE_DIR:odbg-python>/..")
    endforeach()
    message(STATUS "odbg-python: building against Python ${Python3_VERSION}")
else()
    message(STATUS "odbg-python: Python3 Development.Embed not found - skipping")
endif()
