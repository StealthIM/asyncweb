#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ============================================================
// 平台判断
// ============================================================

#if defined(_WIN32) || defined(_WIN64)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET anet_palsock_t;
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    typedef int anet_palsock_t;
#endif


// ============================================================
// 错误码统一（同一组错误码跨平台）
// ============================================================

typedef enum anet_palsock_err_t {
    PALSOCK_OK = 0,
    PALSOCK_ERR_UNKNOWN,
    PALSOCK_ERR_AGAIN,       // EAGAIN / WSAEWOULDBLOCK
    PALSOCK_ERR_CONN_RESET,
    PALSOCK_ERR_CLOSED,
    PALSOCK_ERR_INVALID,
    PALSOCK_ERR_ADDR,
    PALSOCK_ERR_NETDOWN,
    PALSOCK_ERR_IN_PROGRESS,
} anet_palsock_err_t;


// 将系统 errno / WSAGetLastError() 转为 anet_palsock_err_t
anet_palsock_err_t anet_palsock_translate_error(int platform_err);


// ============================================================
// 初始化 / 清理（仅 Windows 需要）
// ============================================================

void anet_palsock_init();    // Windows: WSAStartup; POSIX: no-op
void anet_palsock_cleanup(); // Windows: WSACleanup; POSIX: no-op


// ============================================================
// 基本 socket 操作
// ============================================================

// 创建 socket
anet_palsock_t anet_palsock_create(int af, int type, int protocol, int async);

// 关闭 socket
void anet_palsock_close(anet_palsock_t s);

// 设置非阻塞模式
int anet_palsock_set_nonblocking(anet_palsock_t s, int enabled);

// 是否有效句柄
int anet_palsock_is_valid(anet_palsock_t s);


// ============================================================
// 连接相关
// ============================================================

// connect（阻塞或非阻塞）
int anet_palsock_connect(anet_palsock_t s, const struct sockaddr *addr, int addrlen);

// bind
int anet_palsock_bind(anet_palsock_t s, const struct sockaddr *addr, int addrlen);

// listen
int anet_palsock_listen(anet_palsock_t s, int backlog);

// accept（返回新的 anet_palsock_t）
anet_palsock_t anet_palsock_accept(anet_palsock_t s, struct sockaddr *addr, int *addrlen);


// ============================================================
// 发送 / 接收（阻塞或非阻塞）
// ============================================================

// recv 返回 >= 0 为字节数，< 0 为错误（用 anet_palsock_translate_error 判断）
int anet_palsock_recv(anet_palsock_t s, void *buf, size_t len, int flags);

// send 返回 >= 0 为字节数，< 0 为错误
int anet_palsock_send(anet_palsock_t s, const void *buf, size_t len, int flags);


// ============================================================
// 地址解析 / DNS
// ============================================================

// IPv4 / IPv6 字符串 → sockaddr
int anet_palsock_parse_addr(const char *host, uint16_t port,
                        struct sockaddr_storage *out_addr,
                     int *out_len);

// DNS 解析（getaddrinfo 的包装）
// 只返回 *一个* IPv4/IPv6 结果（简化）
int anet_palsock_resolve(const char *hostname,
                     struct sockaddr_storage *out_addr,
                  int *out_len);


// ============================================================
// Socket 选项
// ============================================================

// TCP_NODELAY
int anet_palsock_set_nodelay(anet_palsock_t s, int enabled);

// SO_REUSEADDR
int anet_palsock_set_reuseaddr(anet_palsock_t s, int enabled);

// SO_KEEPALIVE
int anet_palsock_set_keepalive(anet_palsock_t s, int enabled);


// ============================================================

#ifdef __cplusplus
}
#endif
