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

    set(COMPILER_OPTIONS
        /utf-8
        /MP
        /O2
        /Ob3
        /GL
        /Gw
        /GS-
        /fp:fast
        /MT
        /W3
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
    )
    
    set(LINKER_OPTIONS
        /LTCG
        /OPT:REF
        /OPT:ICF=3
        /INCREMENTAL:NO
        /DEBUG:NONE
        /MERGE:.rdata=.text
    )
else()
    set(COMPILER_OPTIONS
        -Oz
        -Wno-deprecated
        -ffunction-sections
        -fdata-sections
        -fvisibility=hidden
        -fno-unwind-tables
        -fno-asynchronous-unwind-tables
        $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions -fno-rtti>
    )

    set(LINKER_OPTIONS
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
        -Wl,--kill-at
        -flto=thin
    )
endif()

foreach(TARGET dse dse_kvc)
    target_include_directories(${TARGET} PRIVATE minhook/include ${CMAKE_SOURCE_DIR})
    set_target_properties(${TARGET} PROPERTIES PREFIX "")
    target_compile_definitions(${TARGET} PRIVATE UNICODE _UNICODE)
    target_link_libraries(${TARGET} PRIVATE shlwapi)

    target_compile_options(${TARGET} PRIVATE ${COMPILER_OPTIONS})
    target_link_options(${TARGET} PRIVATE ${LINKER_OPTIONS})

    if(MSVC)
        target_compile_definitions(${TARGET} PRIVATE _M_X64 _AMD64_)
    endif()
endforeach()

target_compile_definitions(dse PRIVATE _STABLE)
