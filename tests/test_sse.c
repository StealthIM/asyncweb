#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

/*
 * SSE (流式) 客户端测试。
 *
 * 起一个裸 async socket 服务端: accept 一条连接, 读掉请求, 回一个
 * text/event-stream 响应 + 若干 data: 事件, 然后关连接。用 anet_async_http_stream
 * 消费, 验证:
 *   - on_event 按顺序收到全部事件, data 内容正确
 *   - 连接关闭后 stream task 干净结束 (future done = ANET_OK)
 *   - ASan 零泄漏 (gen_emit 路径 + stream 清理)
 *
 * server 与 client 在同一 loop 里并发推进 (单协程先起 server accept task,
 * 再起 client stream task, 轮询等 client 完成)。
 */

#define SSE_N 4

static const char *g_expect[SSE_N] = { "hello", "world", "sse-event-3", "final" };
static int   g_got = 0;
static char  g_recv[SSE_N][64];
static uint16_t g_port;
static anet_listener_t *g_listener;
static int   g_client_done = 0;
static anet_status_t g_client_status;

static void on_event(const anet_sse_event_t *ev, void *userdata) {
    (void)userdata;
    if (g_got < SSE_N) {
        snprintf(g_recv[g_got], sizeof(g_recv[g_got]), "%.*s", (int)ev->len, ev->data);
    }
    g_got++;
}

/* 裸 server: accept, 读请求, 回 SSE 响应 + N 个 data: 事件, 关连接。 */
task_t* task(sse_server_task) {
    gen_dec_vars(
        future_t      *fut;
        anet_socket_t *conn;
        char           reqbuf[2048];
        char           frame[128];
        int            i;
    );
    gen_begin(ctx);

    gen_var(fut) = anet_socket_accept(g_listener);
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { gen_return(NULL); }
    gen_var(conn) = (anet_socket_t*)future_result(gen_var(fut));

    // 读掉客户端请求 (一次即可)
    gen_var(fut) = anet_socket_recv(gen_var(conn), gen_var(reqbuf), sizeof(gen_var(reqbuf)));
    gen_yield(gen_var(fut));

    // 回 SSE 响应头 (无 Content-Length, 常驻流)
    {
        static const char *hdr =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "\r\n";
        gen_var(fut) = anet_socket_send(gen_var(conn), hdr, strlen(hdr));
        gen_yield(gen_var(fut));
    }

    // 逐个发 data: 事件
    for (gen_var(i) = 0; gen_var(i) < SSE_N; gen_var(i)++) {
        int n = snprintf(gen_var(frame), sizeof(gen_var(frame)), "data: %s\n\n", g_expect[gen_var(i)]);
        gen_var(fut) = anet_socket_send(gen_var(conn), gen_var(frame), n);
        gen_yield(gen_var(fut));
        if (future_is_rejected(gen_var(fut))) break;
    }

    // 关连接 —— 通知客户端流结束
    anet_socket_close(gen_var(conn));
    free(gen_var(conn));
    gen_return(NULL);
    gen_end(NULL);
}

/* 消费 SSE 的 client task 完成时记录状态 */
static void client_done_cb(future_t *fut, void *userdata) {
    (void)userdata;
    g_client_done = 1;
    g_client_status = anet_status_of(future_result(fut));
}

task_t* task(sse_driver_task) {
    gen_dec_vars(
        task_t                  *server_task;
        task_t                  *client_task;
        anet_async_http_request_t req;
        char                     path[32];
        char                     host[16];
    );
    gen_begin(ctx);

    // 起 server accept (分离协程)
    gen_var(server_task) = sse_server_task();
    task_run(gen_var(server_task));

    // 起 client 流式请求
    snprintf(gen_var(host), sizeof(gen_var(host)), "127.0.0.1");
    snprintf(gen_var(path), sizeof(gen_var(path)), "/events");
    memset(&gen_var(req), 0, sizeof(gen_var(req)));
    gen_var(req).method = "GET";
    gen_var(req).host = gen_var(host);
    gen_var(req).port = g_port;
    gen_var(req).use_tls = 0;
    gen_var(req).path = gen_var(path);
    gen_var(req).headers = NULL;
    gen_var(req).body = NULL;

    gen_var(client_task) = anet_async_http_stream(&gen_var(req), on_event, NULL);
    if (!gen_var(client_task)) { printf("stream task create failed\n"); exit(1); }
    future_add_done_callback(gen_var(client_task)->future, client_done_cb, NULL);
    task_run(gen_var(client_task));

    // 等 client 流结束
    while (!g_client_done) {
        gen_yield(async_sleep(5));
    }

    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_sse() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }

    anet_palsock_t ls = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(ls)) { printf("listen create failed\n"); return 1; }
    anet_palsock_set_reuseaddr(ls, 1);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    if (anet_palsock_bind(ls, (struct sockaddr*)&sin, sizeof(sin)) != 0) { printf("bind failed\n"); return 1; }
    if (anet_palsock_listen(ls, 4) != 0) { printf("listen failed\n"); return 1; }
    int blen = sizeof(sin);
    anet_palsock_getsockname(ls, (struct sockaddr*)&sin, &blen);
    g_port = ntohs(sin.sin_port);
    g_listener = anet_listener_create(ls);
    printf("SSE server on 127.0.0.1:%u\n", g_port);

    loop_run(sse_driver_task());

    anet_listener_close(g_listener);
    free(g_listener);
    anet_cleanup();

    // 校验
    if (g_client_status != ANET_OK) { printf("client stream ended with ERR\n"); return 1; }
    if (g_got != SSE_N) { printf("expected %d events, got %d\n", SSE_N, g_got); return 1; }
    for (int i = 0; i < SSE_N; i++) {
        printf("event[%d] = '%s'\n", i, g_recv[i]);
        if (strcmp(g_recv[i], g_expect[i]) != 0) {
            printf("event %d mismatch: got '%s' want '%s'\n", i, g_recv[i], g_expect[i]);
            return 1;
        }
    }
    printf("SSE test passed\n");
    return 0;
}
