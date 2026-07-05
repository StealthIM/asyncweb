#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ============================================================
// 平台判断
// ============================================================

#if defined(LIBCORO_LWIP)
    // lwIP 后端: socket/sockaddr 全部用 lwIP 的定义 (与系统 socket 是两个
    // 命名空间, struct sockaddr 布局也不同, 不能混)。fd 是 lwip_socket 返回的 int。
    #include "lwip/sockets.h"
    #include "lwip/inet.h"
    #include "lwip/netdb.h"
    typedef int anet_palsock_t;
#elif defined(_WIN32) || defined(_WIN64)
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

// 取 socket 本地绑定地址（port==0 时查内核选的临时端口）。成功返回 0。
int anet_palsock_getsockname(anet_palsock_t s, struct sockaddr *addr, int *addrlen);


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
// 只返回 *一个* 结果（简化）。af_hint 指定地址族偏好:
//   AF_UNSPEC = 任意(v4/v6 皆可)、AF_INET = 只要 v4、AF_INET6 = 只要 v6。
// 调用方按返回的 out_addr->ss_family 创建对应 socket。
int anet_palsock_resolve(const char *hostname,
                     int af_hint,
                     struct sockaddr_storage *out_addr,
                  int *out_len);

// 异步 DNS 解析:把阻塞的 getaddrinfo offload 到 libcoro 线程池,
// 返回一个 future,其 result 是一个堆分配的 anet_resolve_result_t*
// (由调用方 free)。future 永远 resolve,失败时 result->ok != 0。
// af_hint 语义同 anet_palsock_resolve。
typedef struct anet_resolve_result_s {
    int ok;                          // 0 成功,-1 失败
    struct sockaddr_storage addr;
    int addr_len;
} anet_resolve_result_t;

struct future_s;
struct future_s *anet_palsock_resolve_async(const char *hostname, int af_hint);


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
