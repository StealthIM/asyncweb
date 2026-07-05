#include "sock/pal_socket.h"
#include "libcoro.h"

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/tcp.h>

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
    return socket(af, type, protocol);
}

void anet_palsock_close(anet_palsock_t s)
{
    if (s >= 0)
        close(s);
}

int anet_palsock_is_valid(anet_palsock_t s)
{
    return s >= 0;
}

int anet_palsock_set_nonblocking(anet_palsock_t s, int enabled)
{
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0)
        return -1;

    if (enabled)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    return fcntl(s, F_SETFL, flags);
}

int anet_palsock_connect(anet_palsock_t s, const struct sockaddr *addr, int addrlen)
{
    return connect(s, addr, addrlen);
}

int anet_palsock_bind(anet_palsock_t s, const struct sockaddr *addr, int addrlen)
{
    return bind(s, addr, addrlen);
}

int anet_palsock_listen(anet_palsock_t s, int backlog)
{
    return listen(s, backlog);
}

anet_palsock_t anet_palsock_accept(anet_palsock_t s, struct sockaddr *addr, int *addrlen)
{
    return accept(s, addr, (socklen_t*)addrlen);
}


// ======================
// send/recv
// ======================

int anet_palsock_recv(anet_palsock_t s, void *buf, size_t len, int flags)
{
    int n = recv(s, buf, len, flags);
    return (n >= 0) ? n : -errno;
}

int anet_palsock_send(anet_palsock_t s, const void *buf, size_t len, int flags)
{
    int n = send(s, buf, len, flags);
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
    if (inet_pton(AF_INET, host, &ipv4) == 1) {
        struct sockaddr_in *addr4 = (struct sockaddr_in*)out_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        addr4->sin_addr = ipv4;
        *out_len = sizeof(struct sockaddr_in);
        return 0;
    }

    struct in6_addr ipv6;
    if (inet_pton(AF_INET6, host, &ipv6) == 1) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)out_addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
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
    // af_hint 直接映射到 getaddrinfo 的地址族偏好:AF_UNSPEC 任意、
    // AF_INET 只 v4、AF_INET6 只 v6。调用方按 out_addr->ss_family 建 socket。
    struct addrinfo hints = {0};
    hints.ai_family = af_hint;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res;
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
        return -1;

    memcpy(out_addr, res->ai_addr, res->ai_addrlen);
    *out_len = (int)res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

// worker 线程的入参:hostname (堆分配,worker 负责 free) + 地址族偏好。
typedef struct {
    char *hostname;
    int   af_hint;
} resolve_job_t;

// 在 worker 线程执行的阻塞解析。返回堆分配的 anet_resolve_result_t*,成为 future 的 result。
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
    return setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                      &enabled, sizeof(enabled));
}

int anet_palsock_set_reuseaddr(anet_palsock_t s, int enabled)
{
    return setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                      &enabled, sizeof(enabled));
}

int anet_palsock_set_keepalive(anet_palsock_t s, int enabled)
{
    return setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                      &enabled, sizeof(enabled));
}
