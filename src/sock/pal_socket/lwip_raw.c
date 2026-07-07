/*
 * asyncweb socket PAL —— 裸机 raw lwIP 后端 (NO_SYS=1)。
 *
 * 和 lwip.c (socket 模式) 的根本差异: 没有 lwip_socket()/fd。anet_palsock_t
 * 是 void* (raw_conn_t* 的 loop handle)。这里只做:
 *   - 非阻塞 setup: create/bind/listen 转发到 libcoro 的 anet_raw_* (建 raw pcb
 *     包装)。socket 本就异步, set_nonblocking 是 no-op。
 *   - DNS: 走 lwIP 原生异步 dns_gethostbyname (回调挂进 loop, 零线程)。裸机
 *     没有可切分的线程池, 阻塞 getaddrinfo 也不存在 (LWIP_NETCONN=0)。
 *
 * 不提供 sync IO (connect/accept/recv/send 的阻塞版) —— 只支持
 * loop 级异步 API。这些函数返回错误/无效值, 上层裸机路径不该调它们。
 */

#include <asyncweb/palsock.h>
#include <libcoro/libcoro.h>
#include <libcoro/loop.h>
#include <libcoro/raw_setup.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "lwip/dns.h"
#include "lwip/ip_addr.h"
#include "lwip/def.h"

/* ====================== 错误码转换 ====================== */

anet_palsock_err_t anet_palsock_translate_error(int e)
{
    switch (e) {
        case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return PALSOCK_ERR_AGAIN;
        case ECONNRESET:   return PALSOCK_ERR_CONN_RESET;
        case ENOTCONN:
        case EPIPE:        return PALSOCK_ERR_CLOSED;
        case EINPROGRESS:  return PALSOCK_ERR_IN_PROGRESS;
        case EADDRNOTAVAIL:
        case EADDRINUSE:   return PALSOCK_ERR_ADDR;
        case ENETDOWN:
        case ENETUNREACH:  return PALSOCK_ERR_NETDOWN;
        default:           return PALSOCK_ERR_UNKNOWN;
    }
}

void anet_palsock_init() {}
void anet_palsock_cleanup() {}

/* ====================== 基础操作 (非阻塞 setup) ====================== */

anet_palsock_t anet_palsock_create(int af, int type, int protocol, int async)
{
    (void)af; (void)type; (void)protocol; (void)async;
    loop_get();                 /* 幂等: 首次拉起 lwIP 栈 (lwip_init) */
    return anet_raw_new_tcp();   /* NULL 表示失败 */
}

void anet_palsock_close(anet_palsock_t s)
{
    if (s) anet_raw_close(s);
}

int anet_palsock_is_valid(anet_palsock_t s) { return s != NULL; }

int anet_palsock_set_nonblocking(anet_palsock_t s, int enabled)
{
    (void)s; (void)enabled;
    return 0;   /* raw pcb 本就异步; 无阻塞模式可切 */
}

int anet_palsock_bind(anet_palsock_t s, const struct sockaddr *addr, int addrlen)
{
    return anet_raw_bind(s, addr, addrlen);
}

int anet_palsock_listen(anet_palsock_t s, int backlog)
{
    return anet_raw_listen(s, backlog);
}

/* ---- sync-only 操作: 裸机不支持 (只走 loop 级异步 API) ---- */

int anet_palsock_connect(anet_palsock_t s, const struct sockaddr *addr, int addrlen)
{
    (void)s; (void)addr; (void)addrlen;
    return -1;   /* 用 anet_socket_connect / loop_connect_async */
}

anet_palsock_t anet_palsock_accept(anet_palsock_t s, struct sockaddr *addr, int *addrlen)
{
    (void)s; (void)addr; (void)addrlen;
    return NULL; /* 用 anet_socket_accept / loop_accept_async */
}

int anet_palsock_recv(anet_palsock_t s, void *buf, size_t len, int flags)
{
    (void)s; (void)buf; (void)len; (void)flags;
    return -1;   /* 用 anet_socket_recv / loop_post_recv */
}

int anet_palsock_send(anet_palsock_t s, const void *buf, size_t len, int flags)
{
    (void)s; (void)buf; (void)len; (void)flags;
    return -1;   /* 用 anet_socket_send / loop_post_send */
}

int anet_palsock_getsockname(anet_palsock_t s, struct sockaddr *addr, int *addrlen)
{
    return anet_raw_getsockname(s, addr, addrlen);
}

/* ====================== socket 选项 (raw pcb 无 setsockopt) ====================== */

int anet_palsock_set_nodelay(anet_palsock_t s, int enabled)   { (void)s; (void)enabled; return 0; }
int anet_palsock_set_reuseaddr(anet_palsock_t s, int enabled) { (void)s; (void)enabled; return 0; }
int anet_palsock_set_keepalive(anet_palsock_t s, int enabled) { (void)s; (void)enabled; return 0; }

/* ====================== DNS ======================
 * 裸机 native-async: dns_gethostbyname 的回调挂进 loop, 零线程。
 * (offload 编译关, 阻塞 getaddrinfo 也不存在。) */

/* IPv4/IPv6 字面量 → sockaddr (不查 DNS)。lwIP 的 ipaddr_aton 不受 LWIP_SOCKET
 * gate 影响, 用它解析字面量。 */
int anet_palsock_parse_addr(const char *host, uint16_t port,
                            struct sockaddr_storage *out_addr, int *out_len)
{
    memset(out_addr, 0, sizeof(*out_addr));

    ip_addr_t ip;
    if (ipaddr_aton(host, &ip)) {
        if (IP_IS_V4(&ip)) {
            struct sockaddr_in *a4 = (struct sockaddr_in*)out_addr;
            a4->sin_family = AF_INET;
            a4->sin_port = lwip_htons(port);
            a4->sin_addr.s_addr = ip_addr_get_ip4_u32(&ip);
            *out_len = (int)sizeof(*a4);
            return 0;
        }
        /* v6 字面量: 裸机 echo 路径暂不用, 不接 */
        return -1;
    }
    /* 非字面量 → 需要 DNS: 同步版拿不到 (裸机异步), 让调用方走 resolve_async。 */
    return -1;
}

/* 同步 resolve: 裸机没有阻塞 DNS。只在 dns 缓存已命中时能立即返回 (ERR_OK)。 */
int anet_palsock_resolve(const char *hostname, int af_hint,
                         struct sockaddr_storage *out_addr, int *out_len)
{
    (void)af_hint;
    ip_addr_t ip;
    /* found=NULL: 只查缓存/字面量, 不发起异步查询 */
    err_t e = dns_gethostbyname(hostname, &ip, NULL, NULL);
    if (e != ERR_OK) return -1;   /* ERR_INPROGRESS 也算失败: 无法同步等 */
    if (!IP_IS_V4(&ip)) return -1;

    memset(out_addr, 0, sizeof(*out_addr));
    struct sockaddr_in *a4 = (struct sockaddr_in*)out_addr;
    a4->sin_family = AF_INET;
    a4->sin_addr.s_addr = ip_addr_get_ip4_u32(&ip);
    *out_len = (int)sizeof(*a4);
    return 0;
}

/* ---- native-async resolve: dns_gethostbyname 回调 → future ---- */

typedef struct {
    future_t *fut;
    uint16_t  port;
} dns_job_t;

/* dns 完成回调 (在 loop 的 dns_tmr / pump 上下文里被调)。 */
static void dns_found_cb(const char *name, const ip_addr_t *ipaddr, void *arg)
{
    (void)name;
    dns_job_t *job = (dns_job_t*)arg;
    anet_resolve_result_t *r = calloc(1, sizeof(*r));
    if (!r) { future_done(job->fut, NULL); free(job); return; }

    if (ipaddr && IP_IS_V4(ipaddr)) {
        struct sockaddr_in *a4 = (struct sockaddr_in*)&r->addr;
        a4->sin_family = AF_INET;
        a4->sin_port = lwip_htons(job->port);
        a4->sin_addr.s_addr = ip_addr_get_ip4_u32(ipaddr);
        r->addr_len = (int)sizeof(*a4);
        r->ok = 0;
    } else {
        r->ok = -1;   /* 解析失败 (ipaddr==NULL) 或非 v4 */
    }
    future_done(job->fut, r);
    free(job);
}

struct future_s *anet_palsock_resolve_async(const char *hostname, int af_hint)
{
    (void)af_hint;   /* 裸机 v4-only */
    if (!hostname) return NULL;
    loop_get();

    future_t *fut = future_create();
    if (!fut) return NULL;
    dns_job_t *job = malloc(sizeof(*job));
    if (!job) { /* future 交给上层驱动销毁 */ future_reject(fut, NULL); return fut; }
    job->fut = fut;
    job->port = 0;   /* 端口由调用方在拿到 addr 后自行填 (同 socket 后端约定) */

    ip_addr_t ip;
    err_t e = dns_gethostbyname(hostname, &ip, dns_found_cb, job);
    if (e == ERR_OK) {
        /* 缓存/字面量命中: 立即完成 (回调不会被调, 手动构造结果) */
        dns_found_cb(hostname, &ip, job);
    } else if (e != ERR_INPROGRESS) {
        /* 立即失败 */
        anet_resolve_result_t *r = calloc(1, sizeof(*r));
        if (r) r->ok = -1;
        future_done(fut, r);
        free(job);
    }
    /* ERR_INPROGRESS: 等 dns_found_cb 异步完成 */
    return fut;
}

