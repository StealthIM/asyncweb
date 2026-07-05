#include "http_server.h"
#include "sock/future_socket.h"
#include "sock/pal_socket.h"
#include "libcoro.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SRV_REQ_MAX    (64 * 1024)
#define SRV_READ_CHUNK 4096

struct anet_http_server {
    anet_palsock_t       listen_sock;
    async_listener_t    *listener;
    anet_http_handler_t  handler;
    void                *userdata;
    uint16_t             port;
    int                  stop;
};

/* ============================================================
 * 每连接处理协程
 * ============================================================ */

typedef struct {
    anet_http_server_t *server;
    async_socket_t     *conn;
    char               *buf;        /* 累积的请求字节 (NUL 结尾) */
    size_t              buf_len;
    size_t              buf_cap;
    char               *out;        /* 构建的响应 */
} conn_ctx_t;

/* 在已读缓冲里定位完整头部。就地把请求行切成 method/path/version。
   返回 0 成功;-1 表示头部尚未完整(需要更多数据)。
   head_len:头部含空行的总长度;headers_start:请求行之后的头部区起点。*/
static int parse_request_head(char *buf, size_t len,
                              char **method_out, char **path_out,
                              char **headers_start_out, size_t *head_len_out) {
    char *he = memmem(buf, len, "\r\n\r\n", 4);
    if (!he) return -1;
    *head_len_out = (size_t)((he + 4) - buf);

    char *rl_end = memmem(buf, len, "\r\n", 2);
    if (!rl_end) return -1;
    *headers_start_out = rl_end + 2;
    *rl_end = '\0';   /* 终止请求行,不影响其后的头部区 */

    char *sp1 = strchr(buf, ' ');
    if (!sp1) return -1;
    *sp1 = '\0';
    char *path = sp1 + 1;
    char *sp2 = strchr(path, ' ');
    if (!sp2) return -1;
    *sp2 = '\0';

    *method_out = buf;
    *path_out = path;
    return 0;
}

/* 在头部区(无内嵌 NUL)大小写不敏感地找 Content-Length。找不到返回 0。*/
static long parse_content_length(const char *headers_start) {
    const char *p = headers_start;
    while (*p) {
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            return atol(p + 15);
        }
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

task_t* task_arg(server_conn_task_) {
    gen_dec_vars(
        conn_ctx_t *c;
        char        chunk[SRV_READ_CHUNK];
        int         n;
        char       *method;
        char       *path;
        char       *headers_start;
        size_t      head_len;
        long        content_len;
        int         have_head;
        future_t   *fut;
    );
    gen_begin(ctx);

    /* task_run 顶层驱动:首个 gen_send 的 arg 为 NULL;conn_ctx 存于 userdata。
       本协程不用 gen_yield_from_task,userdata 不会被改写。 */
    gen_var(c) = (conn_ctx_t*)gen_userdata();
    gen_var(have_head) = 0;
    gen_var(content_len) = 0;
    gen_var(head_len) = 0;

    /* --- 读请求,直到拿到完整头部 + body --- */
    while (1) {
        gen_var(fut) = async_socket_recv(gen_var(c)->conn, gen_var(chunk), sizeof(gen_var(chunk)));
        gen_yield(gen_var(fut));
        gen_var(n) = (int)anet_code_of(future_result(gen_var(fut)));
        if (gen_var(n) <= 0) {
            gen_return(anet_res_status(ANET_ERR));
        }

        if (gen_var(c)->buf_len + gen_var(n) > gen_var(c)->buf_cap) {
            size_t ncap = gen_var(c)->buf_cap ? gen_var(c)->buf_cap * 2 : SRV_READ_CHUNK * 2;
            while (ncap < gen_var(c)->buf_len + gen_var(n)) ncap *= 2;
            if (ncap > SRV_REQ_MAX) { gen_return(anet_res_status(ANET_ERR)); }
            char *nb = realloc(gen_var(c)->buf, ncap + 1);
            if (!nb) { gen_return(anet_res_status(ANET_ERR)); }
            gen_var(c)->buf = nb;
            gen_var(c)->buf_cap = ncap;
        }
        memcpy(gen_var(c)->buf + gen_var(c)->buf_len, gen_var(chunk), gen_var(n));
        gen_var(c)->buf_len += gen_var(n);
        gen_var(c)->buf[gen_var(c)->buf_len] = '\0';

        if (!gen_var(have_head)) {
            if (parse_request_head(gen_var(c)->buf, gen_var(c)->buf_len,
                                   &gen_var(method), &gen_var(path),
                                   &gen_var(headers_start), &gen_var(head_len)) == 0) {
                gen_var(have_head) = 1;
                gen_var(content_len) = parse_content_length(gen_var(headers_start));
            }
        }
        if (gen_var(have_head) &&
            gen_var(c)->buf_len >= gen_var(head_len) + (size_t)gen_var(content_len)) {
            break;
        }
    }

    /* --- 调 handler,构建并发送响应 --- */
    {
        anet_http_server_request_t sreq;
        anet_http_server_response_t sresp;
        sreq.method = gen_var(method);
        sreq.path = gen_var(path);
        sreq.body = gen_var(content_len) > 0 ? gen_var(c)->buf + gen_var(head_len) : NULL;
        sreq.body_len = (size_t)gen_var(content_len);

        sresp.status_code = 200;
        sresp.status_text = "OK";
        sresp.content_type = "text/plain";
        sresp.body = NULL;
        sresp.body_len = 0;

        gen_var(c)->server->handler(&sreq, &sresp, gen_var(c)->server->userdata);

        size_t blen = sresp.body_len;
        if (sresp.body && blen == 0) blen = strlen(sresp.body);

        size_t cap = 256 + blen;
        gen_var(c)->out = malloc(cap);
        if (!gen_var(c)->out) { gen_return(anet_res_status(ANET_ERR)); }
        int hn = snprintf(gen_var(c)->out, cap,
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n",
            sresp.status_code, sresp.status_text,
            sresp.content_type, blen);
        if (sresp.body && blen > 0) {
            memcpy(gen_var(c)->out + hn, sresp.body, blen);
        }

        gen_var(fut) = async_socket_send(gen_var(c)->conn, gen_var(c)->out, (size_t)hn + blen);
        gen_yield(gen_var(fut));
        (void)future_result(gen_var(fut));
    }

    gen_return(anet_res_status(ANET_OK));

    gen_cleanup();
    if (gen_var(c)) {
        if (gen_var(c)->conn) {
            async_socket_close(gen_var(c)->conn);
            free(gen_var(c)->conn);
        }
        free(gen_var(c)->buf);
        free(gen_var(c)->out);
        free(gen_var(c));
        gen_var(c) = NULL;
    }
    gen_end(NULL);
}

/* ============================================================
 * accept 循环协程
 * ============================================================ */

task_t* task_arg(server_accept_task_) {
    gen_dec_vars(
        anet_http_server_t *server;
        future_t           *accept_fut;
        async_socket_t     *conn;
        conn_ctx_t         *cc;
        task_t             *conn_task;
    );
    gen_begin(ctx);

    /* 本协程经 task_run 顶层驱动,首个 gen_send 的 arg 为 NULL;
       构造时传入的 server 存于 userdata。本循环不用 gen_yield_from_task,
       userdata 不会被改写。 */
    gen_var(server) = (anet_http_server_t*)gen_userdata();

    while (1) {
        gen_var(accept_fut) = async_socket_accept(gen_var(server)->listener);
        gen_yield(gen_var(accept_fut));

        if (gen_var(server)->stop) {
            /* stop() 通过 self-connect 唤醒了我们:关掉这条唤醒连接后退出 */
            if (future_is_done(gen_var(accept_fut))) {
                async_socket_t *s = (async_socket_t*)future_result(gen_var(accept_fut));
                if (s) { async_socket_close(s); free(s); }
            }
            break;
        }
        if (future_is_rejected(gen_var(accept_fut))) {
            break;
        }

        gen_var(conn) = (async_socket_t*)future_result(gen_var(accept_fut));

        /* 每连接派生一个分离协程:完成后由 task driver 自动销毁 */
        gen_var(cc) = calloc(1, sizeof(conn_ctx_t));
        if (!gen_var(cc)) {
            async_socket_close(gen_var(conn));
            free(gen_var(conn));
            continue;
        }
        gen_var(cc)->server = gen_var(server);
        gen_var(cc)->conn = gen_var(conn);
        gen_var(conn_task) = server_conn_task_(gen_var(cc));
        if (!gen_var(conn_task)) {
            async_socket_close(gen_var(conn));
            free(gen_var(conn));
            free(gen_var(cc));
            continue;
        }
        task_run(gen_var(conn_task));
    }

    gen_return(NULL);
    gen_end(NULL);
}

/* ============================================================
 * 生命周期
 * ============================================================ */

anet_http_server_t* anet_http_server_create(uint16_t port,
                                            anet_http_handler_t handler,
                                            void *userdata) {
    if (!handler) return NULL;

    anet_palsock_t s = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(s)) return NULL;
    anet_palsock_set_reuseaddr(s, 1);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(port);
    if (anet_palsock_bind(s, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
        anet_palsock_close(s);
        return NULL;
    }
    if (anet_palsock_listen(s, 16) != 0) {
        anet_palsock_close(s);
        return NULL;
    }

    /* 取实际端口 (port==0 时为临时端口) */
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    uint16_t actual = port;
    if (getsockname(s, (struct sockaddr*)&bound, &blen) == 0) {
        actual = ntohs(bound.sin_port);
    }

    anet_http_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) { anet_palsock_close(s); return NULL; }
    srv->listen_sock = s;
    srv->listener = async_listener_create(s);
    srv->handler = handler;
    srv->userdata = userdata;
    srv->port = actual;
    srv->stop = 0;

    if (!srv->listener) {
        anet_palsock_close(s);
        free(srv);
        return NULL;
    }
    return srv;
}

uint16_t anet_http_server_port(anet_http_server_t *server) {
    return server ? server->port : 0;
}

task_t* anet_http_server_run(anet_http_server_t *server) {
    if (!server) return NULL;
    return server_accept_task_(server);
}

void anet_http_server_stop(anet_http_server_t *server) {
    if (!server || server->stop) return;
    server->stop = 1;

    /* self-connect 唤醒阻塞中的 accept。loopback 上 connect 立即成功。 */
    anet_palsock_t w = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 0);
    if (anet_palsock_is_valid(w)) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = htons(server->port);
        anet_palsock_connect(w, (struct sockaddr*)&sin, sizeof(sin));
        anet_palsock_close(w);
    }
}

void anet_http_server_destroy(anet_http_server_t *server) {
    if (!server) return;
    if (server->listener) {
        async_listener_close(server->listener);
        free(server->listener);
    }
    free(server);
}

