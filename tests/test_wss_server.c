#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#if defined(_WIN32) || defined(_WIN64)
#  include <direct.h>
#  define make_dir(p) _mkdir(p)
#  define change_dir(p) _chdir(p)
#else
#  include <unistd.h>
#  define make_dir(p) mkdir((p), 0700)
#  define change_dir(p) chdir(p)
#endif
#include "libcoro.h"
#include "asyncweb.h"
#include "test_certs.h"

/*
 * WSS (WebSocket over TLS) 服务端端到端测试:
 *   - 用预生成的自签名证书 (SAN IP:127.0.0.1),与 TLS 后端解耦
 *   - 服务端:accept 一条连接 → anet_async_ws_accept_tls 先 TLS 握手再 WS 升级
 *     → recv 一条消息 → echo → 关闭
 *   - 客户端:wss://127.0.0.1:port 连接 (完整校验 cert 链 + hostname) → send
 *     → recv echo → 校验
 *   - 在临时子目录里跑,把证书拷进去作 ./cacert.pem
 */

#define WSS_TEST_MSG "hello secure websocket"

static anet_palsock_t    g_listen_sock;
static async_listener_t *g_listener;
static uint16_t          g_port;

/* --- 服务端协程 --- */
task_t* task(wss_server_task) {
    gen_dec_vars(
        future_t        *accept_fut;
        async_socket_t  *conn;
        anet_async_ws_t *ws;
        anet_ws_message_t msg;
        task_t          *task;
    );
    gen_begin(ctx);

    gen_var(accept_fut) = async_socket_accept(g_listener);
    gen_yield(gen_var(accept_fut));
    if (future_is_rejected(gen_var(accept_fut))) { printf("server accept failed\n"); exit(1); }
    gen_var(conn) = (async_socket_t*)future_result(gen_var(accept_fut));

    /* TLS 握手 + WS 升级 */
    gen_var(task) = anet_async_ws_accept_tls(gen_var(conn), "cert.pem", "key.pem", &gen_var(ws));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server wss handshake failed\n"); exit(1);
    }
    printf("server: wss handshake done\n");

    gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server recv failed\n"); exit(1);
    }
    printf("server received: %s\n", gen_var(msg).data);

    gen_var(task) = anet_async_ws_send(gen_var(ws), gen_var(msg).type,
                                       gen_var(msg).data, gen_var(msg).len);
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server echo failed\n"); exit(1);
    }
    anet_ws_message_free(&gen_var(msg));

    gen_var(task) = anet_async_ws_close(gen_var(ws));
    gen_yield_from_task(gen_var(task));
    anet_async_ws_destroy(gen_var(ws));

    printf("server: done\n");
    gen_return(0);
    gen_end(NULL);
}

/* --- 客户端协程 --- */
task_t* task(wss_client_task) {
    gen_dec_vars(
        anet_async_ws_t *ws;
        anet_ws_message_t msg;
        task_t          *task;
        char             url[128];
    );
    gen_begin(ctx);

    snprintf(gen_var(url), sizeof(gen_var(url)), "wss://127.0.0.1:%u/", g_port);
    gen_var(task) = anet_async_ws_connect(gen_var(url), &gen_var(ws));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) == NULL) { printf("client connect failed\n"); exit(1); }
    printf("client: connected\n");

    gen_var(task) = anet_async_ws_send(gen_var(ws), ANET_WS_TEXT, WSS_TEST_MSG, strlen(WSS_TEST_MSG));
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
    if (strcmp(gen_var(msg).data, WSS_TEST_MSG) != 0) {
        printf("echo mismatch: '%s'\n", gen_var(msg).data); exit(1);
    }
    anet_ws_message_free(&gen_var(msg));

    gen_var(task) = anet_async_ws_close(gen_var(ws));
    gen_yield_from_task(gen_var(task));
    anet_async_ws_destroy(gen_var(ws));

    printf("WSS server test passed\n");
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_wss_server() {
    /* 在临时子目录里跑:把预生成证书拷进去作 ./cacert.pem,不污染仓库工作树 */
    make_dir("wss_test_tmp");
    if (change_dir("wss_test_tmp") != 0) { printf("chdir failed\n"); return 1; }
    if (copy_test_certs() != 0) { printf("copy certs failed\n"); return 1; }

    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }

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
        struct sockaddr_in bound; socklen_t bl = sizeof(bound);
        getsockname(g_listen_sock, (struct sockaddr*)&bound, &bl);
        g_port = ntohs(bound.sin_port);
    }
    g_listener = async_listener_create(g_listen_sock);
    printf("wss server listening on 127.0.0.1:%u\n", g_port);

    task_t *st = wss_server_task();
    task_run(st);
    task_t *ct = wss_client_task();
    loop_run(ct);

    async_listener_close(g_listener);
    free(g_listener);
    anet_cleanup();
    return 0;
}
