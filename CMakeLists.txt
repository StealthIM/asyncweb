cmake_minimum_required(VERSION 3.16)
project(asyncweb VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)


# Option
# ASYNCWEB_STANDALONE 只控制"是否编测试"; libcoro 的获取由下面的
# find_package-or-fetch 逻辑自动处理 (装了就 find_package, 没装就 FetchContent)。
option(ASYNCWEB_STANDALONE "Build asyncweb tests" OFF)

set(ASYNCWEB_OS_BACKEND "" CACHE STRING "Choose OS backend: posix, win, lwip")
set_property(CACHE ASYNCWEB_OS_BACKEND PROPERTY STRINGS posix win lwip)

set(ASYNCWEB_SSL_BACKEND "" CACHE STRING "Choose SSL backend: openssl, wolfssl")
set_property(CACHE ASYNCWEB_SSL_BACKEND PROPERTY STRINGS openssl wolfssl)


# ---- 获取 libcoro: 优先系统已装 (find_package), 否则 FetchContent 源码 ----
# 若父项目已经 add_subdirectory/FetchContent 了 libcoro (target 已存在), 直接用。
#
# ASYNCWEB_LIBCORO_INTERNAL: libcoro 是否源码内建 (裸 target, 不可随 asyncweb
# 导出)。find_package 得到的是 IMPORTED target, 可导出 => OFF; FetchContent/
# 上层已存在的裸 target 不可进 export set => ON, 此时跳过 install/export。
set(ASYNCWEB_LIBCORO_INTERNAL ON)
if(NOT TARGET libcoro AND NOT TARGET libcoro::libcoro)
    find_package(libcoro QUIET)
    if(libcoro_FOUND)
        set(ASYNCWEB_LIBCORO_INTERNAL OFF)   # IMPORTED, 可导出
    else()
        include(FetchContent)
        FetchContent_Declare(
                libcoro
                GIT_REPOSITORY https://github.com/StealthIM/libcoro.git
                GIT_TAG master
        )
        if(NOT DEFINED LIBCORO_OS_BACKEND)
            # 注意: 必须写进 cache —— libcoro 把 LIBCORO_OS_BACKEND 声明为 cache
            # 变量, 普通变量会被它的 set(...CACHE) 在子作用域里清掉 (CMP0126)。
            if(WIN32)
                set(_aw_lc_backend "win")
            elseif(UNIX)
                message(WARNING "Use default epoll backend. You can switch to select backend if needed.")
                set(_aw_lc_backend "epoll")
            else()
                message(FATAL_ERROR "No valid OS backend. Please choose one of them.")
            endif()
            set(LIBCORO_OS_BACKEND "${_aw_lc_backend}" CACHE STRING "libcoro OS backend" FORCE)
        endif()
        FetchContent_MakeAvailable(libcoro)
    endif()
endif()

# 统一用 namespaced alias: 无论 libcoro 来自 find_package (libcoro::libcoro)
# 还是 FetchContent/add_subdirectory (裸 target libcoro), 下面都链 libcoro::libcoro。
if(TARGET libcoro AND NOT TARGET libcoro::libcoro)
    add_library(libcoro::libcoro ALIAS libcoro)
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
    # 优先系统已装的 wolfSSL (find_package → IMPORTED target, 可随 asyncweb 导出);
    # 没装则 FetchContent 源码 (built target, 不可导出 → asyncweb 转为不可安装)。
    find_package(wolfssl QUIET)
    if(wolfssl_FOUND)
        target_link_libraries(asyncweb PUBLIC wolfssl)
        set(ASYNCWEB_WOLFSSL_INTERNAL OFF)
    else()
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
        if(WIN32)
            target_compile_definitions(wolfssl PUBLIC USE_WINDOWS_API)
        endif()
        target_link_libraries(asyncweb PUBLIC wolfssl)
        set(ASYNCWEB_WOLFSSL_INTERNAL ON)   # 源码内建, 不可导出安装
    endif()
else()
    message(FATAL_ERROR "No valid SSL backend selected.")
endif()


target_sources(asyncweb PRIVATE ${SRC_FILES})

target_include_directories(asyncweb
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        # 内部头 (<asyncweb_internal/...>): 仅库自身编译可见, 不安装。
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(asyncweb PUBLIC libcoro::libcoro)

# 后端一致性: asyncweb lwip PAL 依赖 libcoro 以 lwip 后端构建 (提供 lwIP 头/符号
# + LIBCORO_LWIP 宏)。把原来隐式的耦合显式化, 不一致直接报错而非编译到一半崩。
if(ASYNCWEB_OS_BACKEND STREQUAL "lwip")
    get_target_property(_lc_defs libcoro::libcoro INTERFACE_COMPILE_DEFINITIONS)
    if(NOT _lc_defs MATCHES "LIBCORO_LWIP")
        message(FATAL_ERROR
            "ASYNCWEB_OS_BACKEND=lwip 需要 libcoro 以 LIBCORO_OS_BACKEND=lwip 构建 "
            "(当前 libcoro 未定义 LIBCORO_LWIP)。请一致选择 lwip 后端。")
    endif()
endif()

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
            tests/test_server_adversarial.c
            tests/test_server_concurrent.c
            tests/test_client_robustness.c
            tests/test_sse.c
    )
    target_link_libraries(test_asyncweb PRIVATE asyncweb)
    # (低层 socket/stream API 现在都在公开 <asyncweb/...> 里, 经 asyncweb PUBLIC
    #  include 传递, 测试无需额外 include 路径。)
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
    add_test_with_dir(test_server_adversarial test_asyncweb server_adversarial)
    add_test_with_dir(test_server_concurrent test_asyncweb server_concurrent)
    add_test_with_dir(test_client_robustness test_asyncweb client_robustness)
    add_test_with_dir(test_sse test_asyncweb sse)
endif()

# ============================================================
# 安装 / 导出 (find_package(asyncweb) + pkg-config)
#
# 前提: 所有 PUBLIC 依赖都是可导出的 (find_package 得到的 IMPORTED target,
# 或已装的 libcoro)。libcoro 或 wolfSSL 走 FetchContent 源码内建时不可导出
# (built target 不能进 export set), 此时跳过 install 并告警 —— 要装 asyncweb
# 请先装 libcoro, 且用系统 wolfSSL (或 openssl 后端)。
# ============================================================
if(ASYNCWEB_LIBCORO_INTERNAL OR ASYNCWEB_WOLFSSL_INTERNAL)
    message(STATUS "asyncweb: 依赖源码内建 (libcoro 或 wolfSSL 非系统安装), 跳过 install/export。"
                   " 装 asyncweb 请先装 libcoro, 并用系统 wolfSSL 或 openssl 后端。")
else()
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# 产物名 libasyncweb.* (target 名已是 asyncweb, 前缀 lib 得 libasyncweb, 符合惯例)。
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/asyncweb
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(TARGETS asyncweb EXPORT asyncwebTargets
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT asyncwebTargets
        FILE asyncwebTargets.cmake
        NAMESPACE asyncweb::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/asyncweb)

# Config 需重新找到 PUBLIC 依赖: libcoro (必) + SSL 后端。记录构建时选的后端。
set(ASYNCWEB_SSL_BACKEND_USED "${ASYNCWEB_SSL_BACKEND}")
configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/asyncwebConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/asyncwebConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/asyncweb)
write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/asyncwebConfigVersion.cmake
        VERSION 1.0.0
        COMPATIBILITY SameMajorVersion)
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/asyncwebConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/asyncwebConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/asyncweb)

# pkg-config
if(ASYNCWEB_SSL_BACKEND STREQUAL "openssl")
    set(ASYNCWEB_PC_REQUIRES "libcoro openssl")
else()
    set(ASYNCWEB_PC_REQUIRES "libcoro")   # wolfssl 无标准 .pc, 靠 Config 侧处理
endif()
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/asyncweb.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/asyncweb.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/asyncweb.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()  # NOT (ASYNCWEB_LIBCORO_INTERNAL OR ASYNCWEB_WOLFSSL_INTERNAL)
