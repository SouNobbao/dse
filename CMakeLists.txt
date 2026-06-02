cmake_minimum_required(VERSION 3.15)
project(dse_dll C CXX)

set(CMAKE_C_COMPILER_TARGET "x86_64-w64-mingw32")
set(CMAKE_CXX_COMPILER_TARGET "x86_64-w64-mingw32")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(dse SHARED
    config.cpp
    checks.cpp
    dllmain.cpp
    events.cpp
    injector.cpp
    patcher.cpp
    log.cpp
    watchdog.cpp
    afterburner.cpp
    hide_module.cpp
    minhook/src/buffer.c
    minhook/src/hook.c
    minhook/src/trampoline.c
    minhook/src/hde/hde64.c
    minhook/src/hde/hde32.c
)

target_include_directories(dse PRIVATE minhook/include)

set_target_properties(dse PROPERTIES PREFIX "")

target_compile_definitions(dse PRIVATE
    _STABLE
    UNICODE
    _UNICODE
)

target_compile_options(dse PRIVATE
    -Wno-deprecated
    $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions -fno-rtti>
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

target_link_options(dse PRIVATE
    -mwindows
    -municode
    -static
    -fuse-ld=lld
    -Wl,--pdb=dse.pdb
)

target_link_libraries(dse PRIVATE
    shlwapi
    psapi
    user32
    kernel32
    advapi32
    shell32
    ole32
    oleaut32
)
