cmake_minimum_required(VERSION 3.16)
project(asyncweb C)

set(CMAKE_C_STANDARD 11)


# Option
option(ASYNCWEB_STANDALONE "Build asyncweb standalone" OFF)

set(ASYNCWEB_OS_BACKEND "" CACHE STRING "Choose OS backend: posix, win")
set_property(CACHE ASYNCWEB_OS_BACKEND PROPERTY STRINGS posix win)

set(ASYNCWEB_SSL_BACKEND "" CACHE STRING "Choose SSL backend: openssl")
set_property(CACHE ASYNCWEB_OS_BACKEND PROPERTY STRINGS openssl)

set(ASYNCWEB_WS "" CACHE STRING "Choose websocket: on/off")
set_property(CACHE ASYNCWEB_WS PROPERTY STRINGS on off)


if(ASYNCWEB_STANDALONE)
    # Libraries
    include(FetchContent)
    FetchContent_Declare(
            libcoro
            GIT_REPOSITORY https://github.com/StealthIM/libcoro.git
            GIT_TAG master
    )
    if(NOT DEFINED LIBCORO_OS_BACKEND)
        if(WIN32)
            set(LIBCORO_OS_BACKEND "win")
        elseif(UNIX)
            message(WARNING "Use default epoll backend. You can switch to select backend if needed.")
            set(LIBCORO_OS_BACKEND "epoll")
        else()
            message(FATAL_ERROR "No valid OS backend. Please choose one of them.")
        endif()
    endif()
    FetchContent_MakeAvailable(libcoro)
endif()

add_library(asyncweb)

list(APPEND SRC_FILES
        src/sync/network/common.c
        src/tools.c
)

if(ASYNCWEB_OS_BACKEND STREQUAL "posix")
    list(APPEND SRC_FILES
            src/sync/network/posix.c
    )
    if(ASYNCWEB_WS STREQUAL "on")
        list(APPEND SRC_FILES
                src/sync/websocket/posix.c
        )
    endif()
elseif(ASYNCWEB_OS_BACKEND STREQUAL "win")
    list(APPEND SRC_FILES
            src/sync/network/win32.c
    )
    target_link_libraries(asyncweb PRIVATE ws2_32 crypt32)
    if(ASYNCWEB_WS STREQUAL "on")
        list(APPEND SRC_FILES
                src/sync/websocket/win32.c
        )
    endif()
else()
    message(FATAL_ERROR "No valid OS backend selected.")
endif()
if(ASYNCWEB_WS STREQUAL "off")
    list(APPEND SRC_FILES
            src/sync/websocket/none.c
    )
endif()
if(ASYNCWEB_SSL_BACKEND STREQUAL "openssl")
    list(APPEND SRC_FILES
            src/tls/openssl.c
    )
    target_link_libraries(asyncweb PRIVATE ssl crypto)
else()
    message(FATAL_ERROR "No valid SSL backend selected.")
endif()


target_sources(asyncweb PRIVATE ${SRC_FILES})

target_include_directories(asyncweb
        PUBLIC
        include/public
        PRIVATE
        include/private
)

target_link_libraries(asyncweb PUBLIC libcoro)

if(ASYNCWEB_STANDALONE)
    enable_testing()
    add_executable(test_asyncweb
            tests/main.c
            tests/test_http.c
    )
    target_link_libraries(test_asyncweb PRIVATE asyncweb)
    add_test(NAME test_http COMMAND test_asyncweb http)
endif()
