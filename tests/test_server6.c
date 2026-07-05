#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* sockaddr_in6 / htons 等由 asyncweb.h -> pal_socket.h 按平台提供。 */
#include "libcoro.h"
#include "asyncweb.h"

/*
 * IPv6 回环测试:验证整条 socket/bind/listen/accept/connect/recv/send 在
 * AF_INET6 (::1) 上工作。与 test_server 同构,但地址族为 IPv6,不依赖外部
 * DNS,直接构造 sockaddr_in6 绑 ::1,是 IPv6 支持的可控端到端证明。
 */

#define TEST_MSG "hello-over-ipv6"

static uint16_t bound_port6(anet_palsock_t s) {
    struct sockaddr_in6 sin6;
    socklen_t len = sizeof(sin6);
    if (getsockname(s, (struct sockaddr*)&sin6, &len) != 0) return 0;
    return ntohs(sin6.sin6_port);
}

task_t* task(server6_test_task) {
    gen_dec_vars(
        anet_palsock_t   listen_sock;
        anet_palsock_t   client_sock;
        async_listener_t *listener;
        async_socket_t   *client;
        async_socket_t   *server_conn;
        future_t         *accept_fut;
        future_t         *connect_fut;
        future_t         *io_fut;
        char              recv_buf[64];
        uint16_t          port;
    );
    gen_begin(ctx);

    /* --- 监听 socket: [::1]:0 --- */
    gen_var(listen_sock) = anet_palsock_create(AF_INET6, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(listen_sock))) { printf("v6 listen create failed\n"); exit(1); }
    anet_palsock_set_reuseaddr(gen_var(listen_sock), 1);

    {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_loopback;   /* ::1 */
        sin6.sin6_port = 0;
        if (anet_palsock_bind(gen_var(listen_sock), (struct sockaddr*)&sin6, sizeof(sin6)) != 0) {
            printf("v6 bind failed\n"); exit(1);
        }
    }
    if (anet_palsock_listen(gen_var(listen_sock), 4) != 0) { printf("v6 listen failed\n"); exit(1); }
    gen_var(port) = bound_port6(gen_var(listen_sock));
    printf("listening on [::1]:%u\n", gen_var(port));

    gen_var(listener) = async_listener_create(gen_var(listen_sock));

    /* --- 客户端 socket (AF_INET6) --- */
    gen_var(client_sock) = anet_palsock_create(AF_INET6, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(client_sock))) { printf("v6 client create failed\n"); exit(1); }
    gen_var(client) = async_socket_create(gen_var(client_sock));

    /* --- 并发 accept + connect 到 [::1]:port --- */
    gen_var(accept_fut) = async_socket_accept(gen_var(listener));
    {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_loopback;
        sin6.sin6_port = htons(gen_var(port));
        gen_var(connect_fut) = async_socket_connect(gen_var(client), (struct sockaddr*)&sin6, sizeof(sin6));
    }

    gen_yield(gen_var(connect_fut));
    if (future_is_rejected(gen_var(connect_fut))) { printf("v6 connect rejected\n"); exit(1); }

    gen_yield(gen_var(accept_fut));
    if (future_is_rejected(gen_var(accept_fut))) { printf("v6 accept rejected\n"); exit(1); }
    gen_var(server_conn) = (async_socket_t*)future_result(gen_var(accept_fut));
    printf("server accepted a v6 connection\n");

    /* --- client -> server --- */
    gen_var(io_fut) = async_socket_send(gen_var(client), TEST_MSG, strlen(TEST_MSG));
    gen_yield(gen_var(io_fut));
    if (future_is_rejected(gen_var(io_fut))) { printf("v6 client send rejected\n"); exit(1); }

    /* --- server recv --- */
    memset(gen_var(recv_buf), 0, sizeof(gen_var(recv_buf)));
    gen_var(io_fut) = async_socket_recv(gen_var(server_conn), gen_var(recv_buf), sizeof(gen_var(recv_buf)) - 1);
    gen_yield(gen_var(io_fut));
    if (future_is_rejected(gen_var(io_fut))) { printf("v6 server recv rejected\n"); exit(1); }
    printf("server received: %s\n", gen_var(recv_buf));

    /* --- server echo --- */
    gen_var(io_fut) = async_socket_send(gen_var(server_conn), gen_var(recv_buf), strlen(gen_var(recv_buf)));
    gen_yield(gen_var(io_fut));
    if (future_is_rejected(gen_var(io_fut))) { printf("v6 server echo rejected\n"); exit(1); }

    /* --- client recv echo --- */
    memset(gen_var(recv_buf), 0, sizeof(gen_var(recv_buf)));
    gen_var(io_fut) = async_socket_recv(gen_var(client), gen_var(recv_buf), sizeof(gen_var(recv_buf)) - 1);
    gen_yield(gen_var(io_fut));
    if (future_is_rejected(gen_var(io_fut))) { printf("v6 client recv rejected\n"); exit(1); }
    printf("client received echo: %s\n", gen_var(recv_buf));

    if (strcmp(gen_var(recv_buf), TEST_MSG) != 0) {
        printf("v6 echo mismatch: got '%s'\n", gen_var(recv_buf));
        exit(1);
    }

    /* --- 清理 --- */
    async_socket_close(gen_var(client));
    free(gen_var(client));
    async_socket_close(gen_var(server_conn));
    free(gen_var(server_conn));
    async_listener_close(gen_var(listener));
    free(gen_var(listener));

    printf("IPv6 loopback test passed\n");
    loop_stop();
    gen_return(0);

    gen_end(NULL);
}

int test_server6() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }
    task_t* t = server6_test_task();
    loop_run(t);
    anet_cleanup();
    return 0;
}
