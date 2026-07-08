cmake_minimum_required(VERSION 3.15)
project(dse_dll C CXX)

# Only target MinGW toolchain when not building with MSVC
if(NOT MSVC)
    set(CMAKE_C_COMPILER_TARGET "x86_64-w64-mingw32")
    set(CMAKE_CXX_COMPILER_TARGET "x86_64-w64-mingw32")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
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
    c_std/vector/vector.c
    c_std/string/std_string.c
)

add_library(dse SHARED ${SOURCES})
add_library(dse_kvc SHARED ${SOURCES})

target_include_directories(dse PRIVATE minhook/include)
target_include_directories(dse PRIVATE ${CMAKE_SOURCE_DIR})
target_include_directories(dse_kvc PRIVATE minhook/include)
target_include_directories(dse_kvc PRIVATE ${CMAKE_SOURCE_DIR})

set_target_properties(dse PROPERTIES PREFIX "")
set_target_properties(dse_kvc PROPERTIES PREFIX "")

target_compile_definitions(dse PRIVATE
    _STABLE
    UNICODE
    _UNICODE
)

target_compile_definitions(dse_kvc PRIVATE
    UNICODE
    _UNICODE
)

# Ensure C sources are compiled as C when using MSVC
if(MSVC)
    set_source_files_properties(
        minhook/src/buffer.c
        minhook/src/hook.c
        minhook/src/trampoline.c
        minhook/src/hde/hde64.c
        minhook/src/hde/hde32.c
        c_std/vector/vector.c
        c_std/string/std_string.c
        PROPERTIES LANGUAGE C
    )
endif()

if(MSVC)
    # MSVC-specific compile options
    set(MSVC_COMPILE_OPTIONS
        /utf-8
        /MP
        /O2
        /Ob3
        /Oi
        /Ot
        /GL
        /Gy
        /Gw
        /GF
        /GS-
        /fp:fast
        /W3
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
    )

    target_compile_options(dse PRIVATE ${MSVC_COMPILE_OPTIONS})
    target_compile_options(dse_kvc PRIVATE ${MSVC_COMPILE_OPTIONS})
    # Define target architecture macros for non-standard MSVC env setups
    target_compile_definitions(dse PRIVATE _M_X64 _AMD64_)
    target_compile_definitions(dse_kvc PRIVATE _M_X64 _AMD64_)
else()
    set(COMMON_COMPILE_OPTIONS
        -Oz
        -Wno-deprecated
        -ffunction-sections
        -fdata-sections
        -fvisibility=hidden
        -fno-unwind-tables
        -fno-asynchronous-unwind-tables
        $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions -fno-rtti>
    )

    target_compile_options(dse PRIVATE ${COMMON_COMPILE_OPTIONS})
    target_compile_options(dse_kvc PRIVATE ${COMMON_COMPILE_OPTIONS})
endif()

if(MSVC)
    set(MSVC_LINK_OPTIONS
        /LTCG
        /OPT:REF
        /OPT:ICF=3
        /INCREMENTAL:NO
        /DEBUG:NONE
        /MERGE:.rdata=.text
    )

    target_link_options(dse PRIVATE ${MSVC_LINK_OPTIONS})
    target_link_options(dse_kvc PRIVATE ${MSVC_LINK_OPTIONS})
else()
    set(COMMON_LINK_OPTIONS
        -Oz
        -static
        -mwindows
        -municode
        -fuse-ld=lld
        -Wl,--gc-sections
        -Wl,--icf=all
        -Wl,--strip-all
        -Wl,--build-id=none
        -Wl,--as-needed
        -flto=thin
    )

    target_link_options(dse PRIVATE ${COMMON_LINK_OPTIONS})
    target_link_options(dse_kvc PRIVATE ${COMMON_LINK_OPTIONS})
endif()

target_link_libraries(dse PRIVATE
    shlwapi
)

target_link_libraries(dse_kvc PRIVATE
    shlwapi
)
