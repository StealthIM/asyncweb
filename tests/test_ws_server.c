#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* sockaddr_in / htons 等由 asyncweb.h -> pal_socket.h 按平台提供。 */
#include "libcoro.h"
#include "asyncweb.h"

/*
 * WebSocket 服务端端到端测试:
 *   - 服务端协程:listener accept 一条连接 → anet_async_ws_accept 完成握手
 *     → recv 一条消息 → 原样 echo 回去 → 关闭
 *   - 客户端协程:ws://127.0.0.1:port 连接 → send → recv echo → 校验
 * 两个协程在同一 loop 上并发驱动。
 */

#define WS_TEST_MSG "hello websocket server"

static anet_palsock_t   g_listen_sock;
static anet_listener_t *g_listener;
static uint16_t          g_port;

/* --- 服务端协程 --- */
task_t* task(ws_server_task) {
    gen_dec_vars(
        future_t        *accept_fut;
        anet_socket_t  *conn;
        anet_async_ws_t *ws;
        anet_ws_message_t msg;
        task_t          *task;
    );
    gen_begin(ctx);

    gen_var(accept_fut) = anet_socket_accept(g_listener);
    gen_yield(gen_var(accept_fut));
    if (future_is_rejected(gen_var(accept_fut))) { printf("server accept failed\n"); exit(1); }
    gen_var(conn) = (anet_socket_t*)future_result(gen_var(accept_fut));

    /* WS 握手 */
    gen_var(task) = anet_async_ws_accept(gen_var(conn), &gen_var(ws));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server ws handshake failed\n"); exit(1);
    }
    printf("server: ws handshake done\n");

    /* recv 一条消息 */
    gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server recv failed\n"); exit(1);
    }
    printf("server received: %s\n", gen_var(msg).data);

    /* echo 回去 */
    gen_var(task) = anet_async_ws_send(gen_var(ws), gen_var(msg).type,
                                       gen_var(msg).data, gen_var(msg).len);
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server echo failed\n"); exit(1);
    }
    anet_ws_message_free(&gen_var(msg));

    /* 关闭并销毁 */
    gen_var(task) = anet_async_ws_close(gen_var(ws));
    gen_yield_from_task(gen_var(task));
    anet_async_ws_destroy(gen_var(ws));

    printf("server: done\n");
    gen_return(0);
    gen_end(NULL);
}

/* --- 客户端协程 --- */
task_t* task(ws_client_task) {
    gen_dec_vars(
        anet_async_ws_t *ws;
        anet_ws_message_t msg;
        task_t          *task;
        char             url[128];
    );
    gen_begin(ctx);

    snprintf(gen_var(url), sizeof(gen_var(url)), "ws://127.0.0.1:%u/", g_port);
    gen_var(task) = anet_async_ws_connect(gen_var(url), &gen_var(ws));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) == NULL) { printf("client connect failed\n"); exit(1); }
    printf("client: connected\n");

    gen_var(task) = anet_async_ws_send(gen_var(ws), ANET_WS_TEXT, WS_TEST_MSG, strlen(WS_TEST_MSG));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("client send failed\n"); exit(1);
    }

    gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("client recv failed\n"); exit(1);
    }
    printf("client received echo: %s\n", gen_var(msg).data);
    if (strcmp(gen_var(msg).data, WS_TEST_MSG) != 0) {
        printf("echo mismatch: '%s'\n", gen_var(msg).data); exit(1);
    }
    anet_ws_message_free(&gen_var(msg));

    gen_var(task) = anet_async_ws_close(gen_var(ws));
    gen_yield_from_task(gen_var(task));
    anet_async_ws_destroy(gen_var(ws));

    printf("WebSocket server test passed\n");
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_ws_server() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }

    /* 建立监听 127.0.0.1:0 */
    g_listen_sock = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(g_listen_sock)) { printf("listen create failed\n"); return 1; }
    anet_palsock_set_reuseaddr(g_listen_sock, 1);
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = 0;
        if (anet_palsock_bind(g_listen_sock, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
            printf("bind failed\n"); return 1;
        }
        if (anet_palsock_listen(g_listen_sock, 4) != 0) { printf("listen failed\n"); return 1; }
        struct sockaddr_in bound; int bl = sizeof(bound);
        anet_palsock_getsockname(g_listen_sock, (struct sockaddr*)&bound, &bl);
        g_port = ntohs(bound.sin_port);
    }
    g_listener = anet_listener_create(g_listen_sock);
    printf("ws server listening on 127.0.0.1:%u\n", g_port);

    /* 服务端协程先跑起来等 accept,再跑客户端 */
    task_t *st = ws_server_task();
    task_run(st);
    task_t *ct = ws_client_task();
    loop_run(ct);

    anet_listener_close(g_listener);
    free(g_listener);
    anet_cleanup();
    return 0;
}
