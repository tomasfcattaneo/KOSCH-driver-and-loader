cmake_minimum_required(VERSION 3.10)
project(KoshcheiLoader LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(src)

add_executable(loader
    src/main.c
    src/tbt.c
    src/svc.c
    src/sysinfo.c
    src/krw.c
    src/gate.c
    src/pe.c
    src/mapper.c
    src/peb.c
    src/resolve.c
    ${CMAKE_SOURCE_DIR}/../shared_protocol.h # Include shared header
    src/cleanup.c
    # Agrega aquí otros archivos .c que tengas en src
)

# Enlazar librerías necesarias de Windows
target_link_libraries(loader PRIVATE Advapi32.lib User32.lib)

if(MSVC)
    # Deshabilitar advertencias de seguridad de funciones antiguas (fopen, etc)
    target_compile_definitions(loader PRIVATE _CRT_SECURE_NO_WARNINGS)
    # Configurar para modo Release optimizado
    set_target_properties(loader PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()