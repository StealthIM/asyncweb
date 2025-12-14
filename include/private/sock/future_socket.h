#pragma once

#include <stddef.h>
#include <stdint.h>
#include "pal_socket.h"
#include "libcoro.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct async_socket async_socket_t;
    typedef struct async_listener async_listener_t;


    // =======================================================
    // socket 生命周期
    // =======================================================

    // 使用已有 pal_sock_t 创建 async socket
    async_socket_t* async_socket_create(anet_palsock_t sock);

    // 关闭（异步安全，可在任意时刻调用）
    void async_socket_close(async_socket_t *s);

    // 获取底层 socket
    anet_palsock_t async_socket_native(async_socket_t *s);


    // =======================================================
    // 单次异步 IO（一个操作 = 一个 future）
    // =======================================================

    // connect（完成或失败）
    future_t* async_socket_connect(async_socket_t *s,
                                   const struct sockaddr *addr,
                                   int addrlen);

    // accept（返回新的 async_socket_t*）
    future_t* async_socket_accept(async_listener_t *listener);

    // recv（一次，可能部分，返回 size_t）
    // 返回 0 表示对端关闭
    future_t* async_socket_recv(async_socket_t *s,
                                void *buf,
                                size_t len);

    // send（一次，可能部分，返回 size_t）
    future_t* async_socket_send(async_socket_t *s,
                                const void *buf,
                                size_t len);


    // =======================================================
    // listener
    // =======================================================

    async_listener_t* async_listener_create(anet_palsock_t listen_sock);

    void async_listener_close(async_listener_t *l);

#ifdef __cplusplus
}
#endif
