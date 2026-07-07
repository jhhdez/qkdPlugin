cmake_minimum_required(VERSION 3.12)
project(qkd-etsi-api VERSION 1.0 LANGUAGES C)

# Generate compile_commands.json so VS Code IntelliSense resolves headers
# without needing a manually maintained c_cpp_properties.json.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Dependencies ─────────────────────────────────────────────────────────────
# HTTP client to the ETSI GS QKD 014 KME REST API.
find_package(CURL REQUIRED)

set(SOURCES
    src/api.c
    src/http.c
)

# ── Library target ────────────────────────────────────────────────────────────
add_library(qkd-etsi-api SHARED ${SOURCES})

target_include_directories(qkd-etsi-api
    PUBLIC
        # Consumers include as <qkd-etsi-api/api.h>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        # Internal sources use shorter paths: #include "api.h"
        ${CMAKE_CURRENT_SOURCE_DIR}/include/qkd-etsi-api
        ${CURL_INCLUDE_DIRS}
)

target_link_libraries(qkd-etsi-api
    PRIVATE ${CURL_LIBRARIES}
)

target_compile_options(qkd-etsi-api PRIVATE
    -Wall -Wno-unused-function -fPIC -O2
)

# ── Install ───────────────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS qkd-etsi-api
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install the single merged header so consumers use:
#   #include <qkd-etsi-api/api.h>
install(FILES include/qkd-etsi-api/api.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qkd-etsi-api
)
