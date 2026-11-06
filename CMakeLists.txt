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
)

set(DRVLOADER_SOURCES
    drvloader/DrvCore.cpp
    drvloader/CiOptionsFinder.cpp
    drvloader/ConfigManager.cpp
    drvloader/SymbolDownloader.cpp
    drvloader/ResourceInstaller.cpp
)

add_library(dse SHARED ${SOURCES} ${DRVLOADER_SOURCES})

# Ensure C sources are compiled as C when using MSVC
if(MSVC)
    set_source_files_properties(
        minhook/src/buffer.c
        minhook/src/hook.c
        minhook/src/trampoline.c
        minhook/src/hde/hde64.c
        minhook/src/hde/hde32.c
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

target_include_directories(dse PRIVATE minhook/include ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/drvloader)
set_target_properties(dse PROPERTIES PREFIX "")
target_compile_definitions(dse PRIVATE UNICODE _UNICODE)
target_link_libraries(dse PRIVATE shlwapi dbghelp winhttp cabinet psapi version shell32 advapi32)

target_compile_options(dse PRIVATE ${COMPILER_OPTIONS})
target_link_options(dse PRIVATE ${LINKER_OPTIONS})

if(MSVC)
    target_compile_definitions(dse PRIVATE _M_X64 _AMD64_)
endif()