#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* sockaddr_in / htons 等由 asyncweb.h -> pal_socket.h 按平台提供。 */
#include "libcoro.h"
#include "asyncweb.h"

/*
 * 服务端回环测试:验证 async_listener / async_socket_accept /
 * async_socket_recv / async_socket_send 这条从未端到端测过的路径。
 *
 * 单协程内同时驱动 server-accept 与 client-connect:两个 future 都 post
 * 到 loop 后并发推进。client 发一段数据,server accept 后 echo 回去,
 * client 收回并校验。
 */

#define TEST_MSG "hello-from-client"

static uint16_t bound_port(anet_palsock_t s) {
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(s, (struct sockaddr*)&sin, &len) != 0) return 0;
    return ntohs(sin.sin_port);
}

task_t* task(server_test_task) {
    gen_dec_vars(
        anet_palsock_t   listen_sock;
        anet_palsock_t   client_sock;
        async_listener_t *listener;
        async_socket_t   *client;      /* 客户端侧 */
        async_socket_t   *server_conn; /* 服务端 accept 到的连接 */
        future_t         *accept_fut;
        future_t         *connect_fut;
        future_t         *io_fut;
        char              recv_buf[64];
        uint16_t          port;
    );
    gen_begin(ctx);

    /* --- 建立监听 socket: 127.0.0.1:0 (临时端口) --- */
    gen_var(listen_sock) = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(listen_sock))) { printf("listen create failed\n"); exit(1); }
    anet_palsock_set_reuseaddr(gen_var(listen_sock), 1);

    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = 0;
        if (anet_palsock_bind(gen_var(listen_sock), (struct sockaddr*)&sin, sizeof(sin)) != 0) {
            printf("bind failed\n"); exit(1);
        }
    }
    if (anet_palsock_listen(gen_var(listen_sock), 4) != 0) { printf("listen failed\n"); exit(1); }
    gen_var(port) = bound_port(gen_var(listen_sock));
    printf("listening on 127.0.0.1:%u\n", gen_var(port));

    gen_var(listener) = async_listener_create(gen_var(listen_sock));

    /* --- 客户端 socket --- */
    gen_var(client_sock) = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(client_sock))) { printf("client create failed\n"); exit(1); }
    gen_var(client) = async_socket_create(gen_var(client_sock));

    /* --- 并发发起 accept 与 connect --- */
    gen_var(accept_fut) = async_socket_accept(gen_var(listener));
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = htons(gen_var(port));
        gen_var(connect_fut) = async_socket_connect(gen_var(client), (struct sockaddr*)&sin, sizeof(sin));
    }

    gen_yield(gen_var(connect_fut));
    if (future_is_rejected(gen_var(connect_fut))) { printf("connect rejected\n"); exit(1); }

    gen_yield(gen_var(accept_fut));
    if (future_is_rejected(gen_var(accept_fut))) { printf("accept rejected\n"); exit(1); }
    gen_var(server_conn) = (async_socket_t*)future_result(gen_var(accept_fut));
    printf("server accepted a connection\n");

    /* --- client -> server --- */
    gen_var(io_fut) = async_socket_send(gen_var(client), TEST_MSG, strlen(TEST_MSG));
    gen_yield(gen_var(io_fut));
    if (future_is_rejected(gen_var(io_fut))) { printf("client send rejected\n"); exit(1); }

    /* --- server recv --- */
    memset(gen_var(recv_buf), 0, sizeof(gen_var(recv_buf)));
    gen_var(io_fut) = async_socket_recv(gen_var(server_conn), gen_var(recv_buf), sizeof(gen_var(recv_buf)) - 1);
    gen_yield(gen_var(io_fut));
    if (future_is_rejected(gen_var(io_fut))) { printf("server recv rejected\n"); exit(1); }
    printf("server received: %s\n", gen_var(recv_buf));

    /* --- server echo back --- */
    gen_var(io_fut) = async_socket_send(gen_var(server_conn), gen_var(recv_buf), strlen(gen_var(recv_buf)));
    gen_yield(gen_var(io_fut));
    if (future_is_rejected(gen_var(io_fut))) { printf("server echo rejected\n"); exit(1); }

    /* --- client recv echo --- */
    memset(gen_var(recv_buf), 0, sizeof(gen_var(recv_buf)));
    gen_var(io_fut) = async_socket_recv(gen_var(client), gen_var(recv_buf), sizeof(gen_var(recv_buf)) - 1);
    gen_yield(gen_var(io_fut));
    if (future_is_rejected(gen_var(io_fut))) { printf("client recv rejected\n"); exit(1); }
    printf("client received echo: %s\n", gen_var(recv_buf));

    if (strcmp(gen_var(recv_buf), TEST_MSG) != 0) {
        printf("echo mismatch: got '%s'\n", gen_var(recv_buf));
        exit(1);
    }

    /* --- 清理 --- */
    async_socket_close(gen_var(client));
    free(gen_var(client));
    async_socket_close(gen_var(server_conn));
    free(gen_var(server_conn));
    async_listener_close(gen_var(listener));
    free(gen_var(listener));

    printf("Server loopback test passed\n");
    loop_stop();
    gen_return(0);

    gen_end(NULL);
}

int test_server() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }
    task_t* t = server_test_task();
    loop_run(t);
    anet_cleanup();
    return 0;
}
