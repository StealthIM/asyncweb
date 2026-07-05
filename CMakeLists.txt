cmake_minimum_required(VERSION 3.16)
project(asyncweb C)

set(CMAKE_C_STANDARD 11)


# Option
option(ASYNCWEB_STANDALONE "Build asyncweb standalone" OFF)

set(ASYNCWEB_OS_BACKEND "" CACHE STRING "Choose OS backend: posix, win, lwip")
set_property(CACHE ASYNCWEB_OS_BACKEND PROPERTY STRINGS posix win lwip)

set(ASYNCWEB_SSL_BACKEND "" CACHE STRING "Choose SSL backend: openssl, wolfssl")
set_property(CACHE ASYNCWEB_SSL_BACKEND PROPERTY STRINGS openssl wolfssl)

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
        src/common.c
        src/tools.c
        src/http.c
        src/http_server.c
        src/ws.c
        src/sock/future_socket.c
        src/sock/stream.c
)

if(ASYNCWEB_OS_BACKEND STREQUAL "posix")
    list(APPEND SRC_FILES
            src/sock/pal_socket/posix.c
    )
elseif(ASYNCWEB_OS_BACKEND STREQUAL "win")
    list(APPEND SRC_FILES
            src/sock/pal_socket/win.c
    )
    target_link_libraries(asyncweb PRIVATE ws2_32 crypt32)
elseif(ASYNCWEB_OS_BACKEND STREQUAL "lwip")
    # lwIP 后端: socket PAL 走 lwip_ 前缀。lwIP 库本身由 libcoro 的 lwip
    # 后端 (LIBCORO_OS_BACKEND=lwip) 通过 lwip_backend 目标 PUBLIC 提供,
    # 所以 asyncweb 只要链 libcoro 就能拿到 lwip 头和符号 (含 LIBCORO_LWIP 宏)。
    list(APPEND SRC_FILES
            src/sock/pal_socket/lwip.c
    )
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
    # Use module mode (builtin FindOpenSSL.cmake) rather than CONFIG mode:
    # it discovers OpenSSL on hosts without an OpenSSLConfig.cmake (e.g.
    # MinGW-w64 cross toolchains) while still working where a config exists.
    find_package(OpenSSL REQUIRED)

    target_link_libraries(asyncweb
            PUBLIC
            OpenSSL::SSL
            OpenSSL::Crypto
    )
elseif(ASYNCWEB_SSL_BACKEND STREQUAL "wolfssl")
    list(APPEND SRC_FILES
            src/tls/wolfssl.c
    )
    # wolfSSL 通过 FetchContent 拉取 (可用 FETCHCONTENT_SOURCE_DIR_WOLFSSL 指向本地
    # 源码免网络)。开启后端所需特性:TLS1.3、自定义 IO 回调、IP alt-name (测试证书
    # 用 IP:127.0.0.1 SAN);关掉 examples/crypttests/install 以缩短构建。
    include(FetchContent)
    set(WOLFSSL_TLS13     "yes" CACHE STRING "" FORCE)
    set(WOLFSSL_IP_ALT_NAME "yes" CACHE STRING "" FORCE)
    set(WOLFSSL_EXAMPLES  "no"  CACHE STRING "" FORCE)
    set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "" FORCE)
    set(WOLFSSL_INSTALL   "no"  CACHE STRING "" FORCE)
    FetchContent_Declare(
            wolfssl
            GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
            GIT_TAG v5.9.2-stable
    )
    FetchContent_MakeAvailable(wolfssl)
    # 交叉编译到 Windows 时,wolfSSL 的 CMake 不会自动定义 USE_WINDOWS_API,
    # 于是种子源退回 POSIX /dev/urandom——在 Wine 下 wc_InitRng 会卡死。
    # 显式打开,让它用 CryptGenRandom (Wine 有实现)。
    if(WIN32)
        target_compile_definitions(wolfssl PUBLIC USE_WINDOWS_API)
    endif()
    target_link_libraries(asyncweb PUBLIC wolfssl)
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
    function(add_test_with_dir test_name executable arg)
        add_test(NAME ${test_name} COMMAND ${executable} ${arg})
        set_tests_properties(${test_name} PROPERTIES
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
    endfunction()

    enable_testing()
    add_executable(test_asyncweb
            tests/main.c
            tests/test_sync_http.c
            tests/test_async_http.c
            tests/test_sync_ws.c
            tests/test_async_ws.c
            tests/test_server.c
            tests/test_server6.c
            tests/test_http_server.c
            tests/test_https_server.c
            tests/test_keepalive.c
            tests/test_ws_server.c
            tests/test_wss_server.c
    )
    target_link_libraries(test_asyncweb PRIVATE asyncweb)
    # keep-alive 测试需要低层 async socket/stream API 建可复用连接
    target_include_directories(test_asyncweb PRIVATE include/private)
    # TLS 测试用预生成证书 (与 TLS 后端解耦);注入绝对路径,测试 chdir 后仍能拷贝
    target_compile_definitions(test_asyncweb PRIVATE
            CERTS_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/certs")
    add_test_with_dir(test_sync_http test_asyncweb sync_http)
    add_test_with_dir(test_async_http test_asyncweb async_http)
    add_test_with_dir(test_sync_ws test_asyncweb sync_ws)
    add_test_with_dir(test_async_ws test_asyncweb async_ws)
    add_test_with_dir(test_server test_asyncweb server)
    add_test_with_dir(test_server6 test_asyncweb server6)
    add_test_with_dir(test_http_server test_asyncweb http_server)
    add_test_with_dir(test_https_server test_asyncweb https_server)
    add_test_with_dir(test_keepalive test_asyncweb keepalive)
    add_test_with_dir(test_ws_server test_asyncweb ws_server)
    add_test_with_dir(test_wss_server test_asyncweb wss_server)
endif()
