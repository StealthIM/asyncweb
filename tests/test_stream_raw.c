#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

/*
 * 通用二进制流读取 (anet_async_http_stream_raw) 测试。
 *
 * 起裸 async server: 回一段带 HTTP header 的响应, body 是已知的 256 字节
 * 二进制序列 (0..255), 然后关连接。客户端用 raw 流式消费, 验证:
 *   - 库跳过 HTTP header, 回调只拿到 body 字节
 *   - body 全部 256 字节按序收全 (可能分多块交付, 累积后比对)
 *   - 连接关后 task 干净结束 (ANET_OK)
 *   - ASan 零泄漏
 */

#define BODY_LEN 256

static unsigned char g_recv[BODY_LEN * 2];   /* 留余量 */
static size_t g_recv_len = 0;
static uint16_t g_port;
static anet_listener_t *g_listener;
static int g_done = 0;
static anet_status_t g_status;

static void on_chunk(const anet_http_chunk_t *chunk, void *userdata) {
    (void)userdata;
    if (g_recv_len + chunk->len <= sizeof(g_recv)) {
        memcpy(g_recv + g_recv_len, chunk->data, chunk->len);
    }
    g_recv_len += chunk->len;
}

task_t* task(raw_server_task) {
    gen_dec_vars(
        future_t      *fut;
        anet_socket_t *conn;
        char           reqbuf[2048];
        unsigned char  body[BODY_LEN];
        char           hdr[128];
        int            i;
    );
    gen_begin(ctx);

    gen_var(fut) = anet_socket_accept(g_listener);
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { gen_return(NULL); }
    gen_var(conn) = (anet_socket_t*)future_result(gen_var(fut));

    gen_var(fut) = anet_socket_recv(gen_var(conn), gen_var(reqbuf), sizeof(gen_var(reqbuf)));
    gen_yield(gen_var(fut));

    // 发 header (带 Content-Length, 但 raw 不解析, 只靠关连接结束)
    {
        int n = snprintf(gen_var(hdr), sizeof(gen_var(hdr)),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %d\r\n"
            "\r\n", BODY_LEN);
        gen_var(fut) = anet_socket_send(gen_var(conn), gen_var(hdr), n);
        gen_yield(gen_var(fut));
    }

    // 发 body: 字节 0..255
    for (gen_var(i) = 0; gen_var(i) < BODY_LEN; gen_var(i)++) {
        gen_var(body)[gen_var(i)] = (unsigned char)gen_var(i);
    }
    gen_var(fut) = anet_socket_send(gen_var(conn), gen_var(body), BODY_LEN);
    gen_yield(gen_var(fut));

    anet_socket_close(gen_var(conn));
    free(gen_var(conn));
    gen_return(NULL);
    gen_end(NULL);
}

static void client_done_cb(future_t *fut, void *userdata) {
    (void)userdata;
    g_done = 1;
    g_status = anet_status_of(future_result(fut));
}

task_t* task(raw_driver_task) {
    gen_dec_vars(
        task_t                   *server_task;
        task_t                   *client_task;
        anet_async_http_request_t req;
        char                      path[32];
        char                      host[16];
    );
    gen_begin(ctx);

    gen_var(server_task) = raw_server_task();
    task_run(gen_var(server_task));

    snprintf(gen_var(host), sizeof(gen_var(host)), "127.0.0.1");
    snprintf(gen_var(path), sizeof(gen_var(path)), "/blob");
    memset(&gen_var(req), 0, sizeof(gen_var(req)));
    gen_var(req).method = "GET";
    gen_var(req).host = gen_var(host);
    gen_var(req).port = g_port;
    gen_var(req).use_tls = 0;
    gen_var(req).path = gen_var(path);

    gen_var(client_task) = anet_async_http_stream_raw(&gen_var(req), on_chunk, NULL);
    if (!gen_var(client_task)) { printf("raw stream task create failed\n"); exit(1); }
    future_add_done_callback(gen_var(client_task)->future, client_done_cb, NULL);
    task_run(gen_var(client_task));

    while (!g_done) {
        gen_yield(async_sleep(5));
    }

    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_stream_raw() {
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
    printf("raw stream server on 127.0.0.1:%u\n", g_port);

    loop_run(raw_driver_task());

    anet_listener_close(g_listener);
    free(g_listener);
    anet_cleanup();

    if (g_status != ANET_OK) { printf("client raw stream ended with ERR\n"); return 1; }
    if (g_recv_len != BODY_LEN) {
        printf("expected %d body bytes, got %zu\n", BODY_LEN, g_recv_len);
        return 1;
    }
    for (int i = 0; i < BODY_LEN; i++) {
        if (g_recv[i] != (unsigned char)i) {
            printf("body byte %d mismatch: got %d\n", i, g_recv[i]);
            return 1;
        }
    }
    printf("raw stream test passed (%zu body bytes, header skipped)\n", g_recv_len);
    return 0;
}
