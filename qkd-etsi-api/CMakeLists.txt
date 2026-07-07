cmake_minimum_required(VERSION 3.12)
project(qkd-etsi-api VERSION 1.0 LANGUAGES C)

# Generate compile_commands.json so VS Code IntelliSense resolves headers
# without needing a manually maintained c_cpp_properties.json.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Backend selection ────────────────────────────────────────────────────────
#
# QKD_BACKEND=simulated  Return a hardcoded 32-byte test key with a freshly
#                        generated UUID.  Both sides return the SAME byte
#                        sequence, so the tunnel comes up without a real KME.
#                        Useful for smoke-testing the IKE handshake.
#
# QKD_BACKEND=http       Call the per-container Flask KME on localhost:8080.
#                        Master SAE uses GET /enc_keys; slave SAE uses POST
#                        /dec_keys.  This is the mode for lab key consumption.
#                        Requires libcurl.
#
set(QKD_BACKEND "simulated" CACHE STRING
    "QKD backend to compile in: simulated | http")
set_property(CACHE QKD_BACKEND PROPERTY STRINGS simulated http)

message(STATUS "qkd-etsi-api: backend = ${QKD_BACKEND}")

# ── Dependencies ─────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)     # base64 encode/decode via BIO
find_package(PkgConfig REQUIRED)
pkg_check_modules(UUID REQUIRED uuid)   # uuid_generate / uuid_parse

set(SOURCES
    src/api.c
    src/simulated.c
)

if(QKD_BACKEND STREQUAL "http")
    find_package(CURL REQUIRED)
    list(APPEND SOURCES src/http.c)
    add_compile_definitions(QKD_USE_HTTP=1)
    message(STATUS "  → HTTP backend via libcurl ${CURL_VERSION}")
else()
    add_compile_definitions(QKD_USE_SIMULATED=1)
    message(STATUS "  → Simulated backend (hardcoded test key)")
endif()

# ── Library target ────────────────────────────────────────────────────────────
add_library(qkd-etsi-api SHARED ${SOURCES})

target_include_directories(qkd-etsi-api
    PUBLIC
        # Consumers include as <qkd-etsi-api/etsi014/api.h>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        # Internal sources use shorter paths: #include "api.h"
        ${CMAKE_CURRENT_SOURCE_DIR}/include/qkd-etsi-api
        ${UUID_INCLUDE_DIRS}
)

target_link_libraries(qkd-etsi-api
    PRIVATE OpenSSL::Crypto ${UUID_LIBRARIES}
)

if(QKD_BACKEND STREQUAL "http")
    target_include_directories(qkd-etsi-api PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(qkd-etsi-api PRIVATE ${CURL_LIBRARIES})
endif()

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
