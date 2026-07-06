#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libcoro.h"
#include "asyncweb.h"
#include "sock/pal_socket.h"
#include "sock/future_socket.h"
#include "sock/stream.h"

/*
 * HTTP keep-alive 端到端测试:
 *   - anet_http_server 起 loopback 服务器,handler 回显 method+path
 *   - 用低层 async socket 建单条连接,串行发两个请求
 *   - 校验两次都在同一连接上拿到 200 + Connection: keep-alive
 *   - 第三个请求带 Connection: close,校验服务端据此关闭
 * 高层异步 HTTP 客户端每请求新建连接,无法验证复用,故此处走裸 stream。
 */

static anet_http_server_t *g_server;

static void echo_handler(const anet_http_server_request_t *req,
                         anet_http_server_response_t *resp,
                         void *userdata) {
    (void)userdata;
    static char body[256];
    snprintf(body, sizeof(body), "%s %s", req->method, req->path);
    resp->status_code = 200;
    resp->status_text = "OK";
    resp->content_type = "text/plain";
    resp->body = body;
}

/* 在 stream 上读一个完整 HTTP 响应 (依 Content-Length) 到 buf。返回长度,失败 -1。*/
task_t* task_arg(read_one_response_) {
    typedef struct { anet_stream_t *s; char *buf; size_t cap; size_t *lenp; } args_t;
    gen_dec_vars(
        args_t a;
        char chunk[1024];
        int n;
        size_t total;
        task_t *task;
    );
    gen_begin(ctx);
    gen_var(a) = *(args_t*)arg;
    free(arg);
    gen_var(total) = 0;

    while (1) {
        gen_var(task) = anet_stream_read(gen_var(a).s, sizeof(gen_var(chunk)), gen_var(chunk));
        gen_yield_from_task(gen_var(task));
        gen_var(n) = (int)anet_code_of(future_result(gen_var(task)->future));
        if (gen_var(n) <= 0) { gen_return((void*)(intptr_t)-1); }
        if (gen_var(total) + gen_var(n) >= gen_var(a).cap) { gen_return((void*)(intptr_t)-1); }
        memcpy(gen_var(a).buf + gen_var(total), gen_var(chunk), gen_var(n));
        gen_var(total) += gen_var(n);
        gen_var(a).buf[gen_var(total)] = '\0';

        char *he = strstr(gen_var(a).buf, "\r\n\r\n");
        if (he) {
            char *cl = strstr(gen_var(a).buf, "Content-Length:");
            if (cl && cl < he) {
                long blen = atol(cl + 15);
                size_t body_start = (size_t)((he + 4) - gen_var(a).buf);
                if (gen_var(total) >= body_start + (size_t)blen) {
                    *gen_var(a).lenp = gen_var(total);
                    gen_return((void*)(intptr_t)gen_var(total));
                }
            }
        }
    }
    gen_end(NULL);
}

task_t* read_one_response(anet_stream_t *s, char *buf, size_t cap, size_t *lenp) {
    struct { anet_stream_t *s; char *buf; size_t cap; size_t *lenp; } *a = malloc(sizeof(*a));
    a->s = s; a->buf = buf; a->cap = cap; a->lenp = lenp;
    return read_one_response_(a);
}

static int check(const char *buf, const char *want_body, int want_keep_alive) {
    if (strncmp(buf, "HTTP/1.1 200", 12) != 0) { printf("bad status: %.20s\n", buf); return 1; }
    char *ka = strstr(buf, "Connection:");
    if (!ka) { printf("no Connection header\n"); return 1; }
    int is_ka = (strstr(ka, "keep-alive") != NULL && strstr(ka, "keep-alive") < strstr(buf, "\r\n\r\n"));
    if (is_ka != want_keep_alive) { printf("keep-alive mismatch: got %d want %d\n", is_ka, want_keep_alive); return 1; }
    char *he = strstr(buf, "\r\n\r\n");
    if (!he || strcmp(he + 4, want_body) != 0) { printf("body mismatch: got '%s' want '%s'\n", he ? he+4 : "(null)", want_body); return 1; }
    return 0;
}

task_t* task(keepalive_client_task) {
    gen_dec_vars(
        task_t *accept_task;
        anet_socket_t *sock;
        anet_stream_t *stream;
        future_t *cfut;
        task_t *task;
        char req[256];
        char buf[4096];
        size_t rlen;
    );
    gen_begin(ctx);

    gen_var(accept_task) = anet_http_server_run(g_server);
    task_run(gen_var(accept_task));

    /* 建单条连接到服务器 */
    gen_var(sock) = anet_socket_create(anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1));
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = htons(anet_http_server_port(g_server));
        gen_var(cfut) = anet_socket_connect(gen_var(sock), (struct sockaddr*)&sin, sizeof(sin));
        gen_yield(gen_var(cfut));
        if (anet_code_of(future_result(gen_var(cfut))) != 0) { printf("connect failed\n"); exit(1); }
    }
    gen_var(stream) = anet_stream_from_socket(gen_var(sock));

    /* --- 请求 1 (keep-alive 默认) --- */
    snprintf(gen_var(req), sizeof(gen_var(req)),
             "GET /one HTTP/1.1\r\nHost: x\r\n\r\n");
    gen_var(task) = anet_stream_write_all(gen_var(stream), gen_var(req), strlen(gen_var(req)));
    gen_yield_from_task(gen_var(task));
    gen_var(task) = read_one_response(gen_var(stream), gen_var(buf), sizeof(gen_var(buf)), &gen_var(rlen));
    gen_yield_from_task(gen_var(task));
    if ((intptr_t)future_result(gen_var(task)->future) < 0) { printf("read 1 failed\n"); exit(1); }
    if (check(gen_var(buf), "GET /one", 1)) { exit(1); }
    printf("req1 OK (keep-alive)\n");

    /* --- 请求 2 复用同一连接 --- */
    snprintf(gen_var(req), sizeof(gen_var(req)),
             "GET /two HTTP/1.1\r\nHost: x\r\n\r\n");
    gen_var(task) = anet_stream_write_all(gen_var(stream), gen_var(req), strlen(gen_var(req)));
    gen_yield_from_task(gen_var(task));
    gen_var(task) = read_one_response(gen_var(stream), gen_var(buf), sizeof(gen_var(buf)), &gen_var(rlen));
    gen_yield_from_task(gen_var(task));
    if ((intptr_t)future_result(gen_var(task)->future) < 0) { printf("read 2 failed\n"); exit(1); }
    if (check(gen_var(buf), "GET /two", 1)) { exit(1); }
    printf("req2 OK (reused connection)\n");

    /* --- 请求 3 显式 close --- */
    snprintf(gen_var(req), sizeof(gen_var(req)),
             "GET /three HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    gen_var(task) = anet_stream_write_all(gen_var(stream), gen_var(req), strlen(gen_var(req)));
    gen_yield_from_task(gen_var(task));
    gen_var(task) = read_one_response(gen_var(stream), gen_var(buf), sizeof(gen_var(buf)), &gen_var(rlen));
    gen_yield_from_task(gen_var(task));
    if ((intptr_t)future_result(gen_var(task)->future) < 0) { printf("read 3 failed\n"); exit(1); }
    if (check(gen_var(buf), "GET /three", 0)) { exit(1); }
    printf("req3 OK (Connection: close honored)\n");

    anet_stream_destroy(gen_var(stream));
    anet_http_server_stop(g_server);

    printf("keep-alive server test passed\n");
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_keepalive() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }

    g_server = anet_http_server_create(0, echo_handler, NULL);
    if (!g_server) { printf("server create failed\n"); return 1; }
    printf("keep-alive server listening on 127.0.0.1:%u\n", anet_http_server_port(g_server));

    task_t *t = keepalive_client_task();
    loop_run(t);

    anet_http_server_destroy(g_server);
    g_server = NULL;
    anet_cleanup();
    return 0;
}
