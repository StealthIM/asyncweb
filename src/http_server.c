#include "http_server.h"
#include "sock/future_socket.h"
#include "sock/pal_socket.h"
#include "sock/stream.h"
#include "tls.h"
#include "libcoro.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/* 网络类型/字节序 (sockaddr_in, htons, INADDR_LOOPBACK 等) 及大小写不敏感
   比较由 pal_socket.h 按平台提供正确的系统头 (winsock2/ws2tcpip 或 netinet)。 */

#define SRV_REQ_MAX    (64 * 1024)
#define SRV_READ_CHUNK 4096

struct anet_http_server {
    anet_palsock_t       listen_sock;
    async_listener_t    *listener;
    anet_http_handler_t  handler;
    void                *userdata;
    uint16_t             port;
    int                  stop;
    int                  tls;         /* 启用 HTTPS */
    char                *cert_path;
    char                *key_path;
};

/* ============================================================
 * 每连接处理协程
 * ============================================================ */

typedef struct {
    anet_http_server_t *server;
    async_socket_t     *conn;         /* accept 到的裸 socket */
    async_ssl_t        *ssl;          /* TLS 会话 (明文时 NULL);attach 后拥有 conn */
    async_stream_t     *stream;       /* 包裹 conn 或 ssl,统一读写 */
    char               *buf;          /* 累积的请求字节 (NUL 结尾) */
    size_t              buf_len;
    size_t              buf_cap;
    char               *out;          /* 构建的响应 */
} conn_ctx_t;

/* 破坏性解析:就地把请求行切成 method/path/version(写入 NUL)。
   仅在缓冲已确认稳定(不再 realloc)后调用,避免悬垂指针。
   headers_start:请求行之后的头部区起点。返回 0 成功,-1 失败。*/
static int parse_request_head(char *buf, size_t head_len,
                              char **method_out, char **path_out,
                              char **version_out, char **headers_start_out) {
    char *rl_end = strstr(buf, "\r\n");
    if (!rl_end || rl_end + 2 > buf + head_len) return -1;
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
    *version_out = sp2 + 1;   /* rl_end 处已置 NUL,version 到此为止 */
    return 0;
}

/* 在头部区 [start, end) 大小写不敏感地找 Content-Length。找不到返回 0。
   end 界定头部结束,防止 body 里的 "Content-Length:" 文本被误匹配。*/
static long parse_content_length(const char *start, const char *end) {
    const char *p = start;
    while (p < end) {
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            long v = atol(p + 15);
            return v > 0 ? v : 0;
        }
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* 非破坏性:判断缓冲里是否已有一个完整请求(头部 + body)。
   完整时输出 head_len(含结尾空行)与 content_len。buf 须 NUL 结尾。*/
static int request_is_complete(const char *buf, size_t buf_len,
                               size_t *head_len_out, long *content_len_out) {
    const char *he = strstr(buf, "\r\n\r\n");
    if (!he) return 0;
    size_t head_len = (size_t)((he + 4) - buf);
    const char *rl_end = strstr(buf, "\r\n");   /* 必存在且 <= he */
    long content_len = parse_content_length(rl_end + 2, he);
    if (buf_len >= head_len + (size_t)content_len) {
        *head_len_out = head_len;
        *content_len_out = content_len;
        return 1;
    }
    return 0;
}

/* 依 RFC7230 判定是否保持连接:HTTP/1.1 默认 keep-alive,HTTP/1.0 默认关闭;
   Connection 头显式 close/keep-alive 覆盖默认。扫描头部区 [start, end)。*/
static int wants_keep_alive(const char *start, const char *end, int http11) {
    const char *p = start;
    while (p < end) {
        if (strncasecmp(p, "Connection:", 11) == 0) {
            const char *v = p + 11;
            const char *nl = memchr(v, '\n', (size_t)(end - v));
            const char *ve = nl ? nl : end;
            for (const char *q = v; q < ve; q++) {
                if (strncasecmp(q, "close", 5) == 0) return 0;
                if (strncasecmp(q, "keep-alive", 10) == 0) return 1;
            }
            return http11;
        }
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        p = nl + 1;
    }
    return http11;
}

task_t* task_arg(server_conn_task_) {
    gen_dec_vars(
        conn_ctx_t *c;
        char        chunk[SRV_READ_CHUNK];
        int         n;
        char       *method;
        char       *path;
        char       *version;
        char       *headers_start;
        size_t      head_len;
        long        content_len;
        size_t      req_total;      /* 本请求占用的字节数 (head_len + body) */
        int         keep_alive;
        task_t     *task;
    );
    gen_begin(ctx);

    /* task_run 顶层驱动:首个 gen_send 的 arg 为 NULL;conn_ctx 存于 userdata。 */
    gen_var(c) = (conn_ctx_t*)gen_userdata();

    /* --- 建立 stream:HTTPS 先做服务端 TLS 握手,否则裸 socket --- */
    if (gen_var(c)->server->tls) {
        gen_var(c)->ssl = async_ssl_create_server(gen_var(c)->server->cert_path,
                                                  gen_var(c)->server->key_path);
        if (!gen_var(c)->ssl) {
            gen_return(anet_res_status(ANET_ERR));
        }
        // ssl attach 后拥有 conn(销毁时一并释放)
        async_ssl_attach_socket(gen_var(c)->ssl, gen_var(c)->conn);
        gen_var(task) = async_ssl_handshake(gen_var(c)->ssl);
        gen_yield_from_task(gen_var(task));
        if (anet_code_of(future_result(gen_var(task)->future)) != 0) {
            gen_return(anet_res_status(ANET_ERR));
        }
        gen_var(c)->stream = async_stream_from_ssl(gen_var(c)->ssl);
    } else {
        gen_var(c)->stream = async_stream_from_socket(gen_var(c)->conn);
    }
    if (!gen_var(c)->stream) {
        gen_return(anet_res_status(ANET_ERR));
    }

    /* === keep-alive 外层循环:每轮处理一个请求 === */
    gen_var(keep_alive) = 1;
    while (gen_var(keep_alive)) {
        /* --- 读请求,直到缓冲里出现完整头部 + body。缓冲可能已含上一轮的
               pipelined 残留 (下方 memmove 保留),先判一次再读。 --- */
        gen_var(head_len) = 0;
        gen_var(content_len) = 0;
        while (!(gen_var(c)->buf_len > 0 &&
                 request_is_complete(gen_var(c)->buf, gen_var(c)->buf_len,
                                     &gen_var(head_len), &gen_var(content_len)))) {
            gen_var(task) = async_stream_read(gen_var(c)->stream, sizeof(gen_var(chunk)), gen_var(chunk));
            gen_yield_from_task(gen_var(task));
            gen_var(n) = (int)anet_code_of(future_result(gen_var(task)->future));
            if (gen_var(n) <= 0) {
                /* 对端关闭或出错。若已发过响应,视为正常收尾。 */
                gen_return(anet_res_status(ANET_OK));
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
        }
        gen_var(req_total) = gen_var(head_len) + (size_t)gen_var(content_len);

        /* --- 缓冲已稳定,破坏性解析请求行 (切出 method/path/version) --- */
        if (parse_request_head(gen_var(c)->buf, gen_var(head_len),
                               &gen_var(method), &gen_var(path),
                               &gen_var(version), &gen_var(headers_start)) != 0) {
            gen_return(anet_res_status(ANET_ERR));
        }
        {
            int http11 = (strcmp(gen_var(version), "HTTP/1.1") == 0);
            /* headers_start .. head_len(相对 buf) 为头部区;body 紧随其后。
               请求行已被 parse_request_head 就地插入 NUL,不影响头部区扫描。 */
            const char *hdr_end = gen_var(c)->buf + gen_var(head_len);
            gen_var(keep_alive) =
                wants_keep_alive(gen_var(headers_start), hdr_end, http11) &&
                !gen_var(c)->server->stop;
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
                "Connection: %s\r\n"
                "\r\n",
                sresp.status_code, sresp.status_text,
                sresp.content_type, blen,
                gen_var(keep_alive) ? "keep-alive" : "close");
            if (sresp.body && blen > 0) {
                memcpy(gen_var(c)->out + hn, sresp.body, blen);
            }

            gen_var(task) = async_stream_write_all(gen_var(c)->stream, gen_var(c)->out, (size_t)hn + blen);
            gen_yield_from_task(gen_var(task));
            int wr = (int)anet_code_of(future_result(gen_var(task)->future));
            free(gen_var(c)->out);
            gen_var(c)->out = NULL;
            if (wr != 0) {
                gen_return(anet_res_status(ANET_ERR));
            }
        }

        /* --- 移除已消费的请求,保留 pipelined 残留供下一轮 --- */
        if (gen_var(c)->buf_len > gen_var(req_total)) {
            memmove(gen_var(c)->buf, gen_var(c)->buf + gen_var(req_total),
                    gen_var(c)->buf_len - gen_var(req_total));
            gen_var(c)->buf_len -= gen_var(req_total);
        } else {
            gen_var(c)->buf_len = 0;
        }
        gen_var(c)->buf[gen_var(c)->buf_len] = '\0';
    }

    gen_return(anet_res_status(ANET_OK));

    gen_cleanup();
    if (gen_var(c)) {
        /* stream 只是壳;async_stream_destroy 释放它并连带底层 ssl 或 socket。
           TLS 时 ssl 拥有 conn;明文时 stream 直接持有 conn。两种情况都由
           stream_destroy 收尾,故不在此单独 close/free conn。 */
        if (gen_var(c)->stream) {
            async_stream_destroy(gen_var(c)->stream);
        } else {
            /* stream 尚未建立(极早失败):自行收 ssl 或 conn */
            if (gen_var(c)->ssl) {
                async_ssl_destroy(gen_var(c)->ssl);
            } else if (gen_var(c)->conn) {
                async_socket_close(gen_var(c)->conn);
                free(gen_var(c)->conn);
            }
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
    int blen = sizeof(bound);
    uint16_t actual = port;
    if (anet_palsock_getsockname(s, (struct sockaddr*)&bound, &blen) == 0) {
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

int anet_http_server_use_tls(anet_http_server_t *server,
                             const char *cert_path,
                             const char *key_path) {
    if (!server || !cert_path || !key_path) return -1;
    char *c = strdup(cert_path);
    char *k = strdup(key_path);
    if (!c || !k) { free(c); free(k); return -1; }
    free(server->cert_path);
    free(server->key_path);
    server->cert_path = c;
    server->key_path = k;
    server->tls = 1;
    return 0;
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
    free(server->cert_path);
    free(server->key_path);
    free(server);
}

