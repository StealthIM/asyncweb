/*
 * asyncweb socket PAL —— lwIP 后端 (阶段 1: UNIX host port)。
 *
 * 基本是 posix.c 换 lwip_ 前缀。socket/sockaddr/DNS 全走 lwIP 命名空间
 * (见 pal_socket.h 的 LIBCORO_LWIP 分支)。errno 仍是系统 TLS errno
 * (lwipopts 用 LWIP_ERRNO_STDINCLUDE, lwip 错误码映射到 <errno.h>)。
 */

#include "sock/pal_socket.h"
#include "libcoro.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"

// ======================
// 错误码转换
// ======================

anet_palsock_err_t anet_palsock_translate_error(int e)
{
    switch (e) {
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return PALSOCK_ERR_AGAIN;
        case ECONNRESET:
            return PALSOCK_ERR_CONN_RESET;
        case ENOTCONN:
        case EPIPE:
            return PALSOCK_ERR_CLOSED;
        case EINPROGRESS:
            return PALSOCK_ERR_IN_PROGRESS;
        case EADDRNOTAVAIL:
        case EADDRINUSE:
            return PALSOCK_ERR_ADDR;
        case ENETDOWN:
        case ENETUNREACH:
            return PALSOCK_ERR_NETDOWN;
        default:
            return PALSOCK_ERR_UNKNOWN;
    }
}

void anet_palsock_init() {}
void anet_palsock_cleanup() {}


// ======================
// 基础操作
// ======================

anet_palsock_t anet_palsock_create(int af, int type, int protocol, int async)
{
    (void)async;
    // lwIP 栈初始化绑在 loop 创建里 (loop_create_sub → ensure_lwip_init)。
    // 高层 API (如 anet_http_server_create) 会在 loop_run 之前就建 socket,
    // 那时栈还没起来, lwip_socket 会锁未初始化的 tcpip mutex 而崩。
    // loop_get() 幂等: 首次调用拉起栈+loop, 之后 loop_run 复用同一个 loop。
    loop_get();
    return lwip_socket(af, type, protocol);
}

void anet_palsock_close(anet_palsock_t s)
{
    if (s >= 0)
        lwip_close(s);
}

int anet_palsock_is_valid(anet_palsock_t s)
{
    return s >= 0;
}

int anet_palsock_set_nonblocking(anet_palsock_t s, int enabled)
{
    int flags = lwip_fcntl(s, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (enabled)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    return lwip_fcntl(s, F_SETFL, flags);
}

int anet_palsock_connect(anet_palsock_t s, const struct sockaddr *addr, int addrlen)
{
    return lwip_connect(s, addr, addrlen);
}

int anet_palsock_bind(anet_palsock_t s, const struct sockaddr *addr, int addrlen)
{
    return lwip_bind(s, addr, addrlen);
}

int anet_palsock_listen(anet_palsock_t s, int backlog)
{
    return lwip_listen(s, backlog);
}

anet_palsock_t anet_palsock_accept(anet_palsock_t s, struct sockaddr *addr, int *addrlen)
{
    return lwip_accept(s, addr, (socklen_t*)addrlen);
}

int anet_palsock_getsockname(anet_palsock_t s, struct sockaddr *addr, int *addrlen)
{
    return lwip_getsockname(s, addr, (socklen_t*)addrlen);
}


// ======================
// send/recv
// ======================

int anet_palsock_recv(anet_palsock_t s, void *buf, size_t len, int flags)
{
    int n = lwip_recv(s, buf, len, flags);
    return (n >= 0) ? n : -errno;
}

int anet_palsock_send(anet_palsock_t s, const void *buf, size_t len, int flags)
{
    int n = lwip_send(s, buf, len, flags);
    return (n >= 0) ? n : -errno;
}


// ======================
// DNS 解析
// ======================

int anet_palsock_parse_addr(const char *host, uint16_t port,
                        struct sockaddr_storage *out_addr,
                        int *out_len)
{
    memset(out_addr, 0, sizeof(*out_addr));

    struct in_addr ipv4;
    if (lwip_inet_pton(AF_INET, host, &ipv4) == 1) {
        struct sockaddr_in *addr4 = (struct sockaddr_in*)out_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = lwip_htons(port);
        addr4->sin_addr = ipv4;
        *out_len = sizeof(struct sockaddr_in);
        return 0;
    }

    struct in6_addr ipv6;
    if (lwip_inet_pton(AF_INET6, host, &ipv6) == 1) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)out_addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = lwip_htons(port);
        addr6->sin6_addr = ipv6;
        *out_len = sizeof(struct sockaddr_in6);
        return 0;
    }

    // 非纯 IP → 用 DNS (任意族)
    return anet_palsock_resolve(host, AF_UNSPEC, out_addr, out_len);
}

int anet_palsock_resolve(const char *hostname,
                     int af_hint,
                     struct sockaddr_storage *out_addr,
                     int *out_len)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af_hint;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res;
    if (lwip_getaddrinfo(hostname, NULL, &hints, &res) != 0)
        return -1;

    memcpy(out_addr, res->ai_addr, res->ai_addrlen);
    *out_len = (int)res->ai_addrlen;

    lwip_freeaddrinfo(res);
    return 0;
}

// worker 线程入参:hostname (堆分配, worker 负责 free) + 地址族偏好。
typedef struct {
    char *hostname;
    int   af_hint;
} resolve_job_t;

static void *resolve_worker(void *arg)
{
    resolve_job_t *job = (resolve_job_t *)arg;
    anet_resolve_result_t *r = calloc(1, sizeof(*r));
    if (!r) { free(job->hostname); free(job); return NULL; }

    if (anet_palsock_resolve(job->hostname, job->af_hint, &r->addr, &r->addr_len) != 0) {
        r->ok = -1;
    } else {
        r->ok = 0;
    }
    free(job->hostname);
    free(job);
    return r;
}

struct future_s *anet_palsock_resolve_async(const char *hostname, int af_hint)
{
    if (!hostname) return NULL;
    resolve_job_t *job = malloc(sizeof(*job));
    if (!job) return NULL;
    job->hostname = strdup(hostname);
    if (!job->hostname) { free(job); return NULL; }
    job->af_hint = af_hint;
    struct future_s *fut = loop_run_in_thread(resolve_worker, job);
    if (!fut) { free(job->hostname); free(job); return NULL; }
    return fut;
}


// ======================
// socket 选项
// ======================

int anet_palsock_set_nodelay(anet_palsock_t s, int enabled)
{
    return lwip_setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                           &enabled, sizeof(enabled));
}

int anet_palsock_set_reuseaddr(anet_palsock_t s, int enabled)
{
    return lwip_setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           &enabled, sizeof(enabled));
}

int anet_palsock_set_keepalive(anet_palsock_t s, int enabled)
{
    return lwip_setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                           &enabled, sizeof(enabled));
}
