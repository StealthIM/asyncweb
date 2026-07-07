#pragma once

#include <stddef.h>
#include <stdint.h>
#include <asyncweb/palsock.h>
#include <libcoro/libcoro.h>
#include <asyncweb/common.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct async_socket anet_socket_t;
    typedef struct async_listener anet_listener_t;


    // =======================================================
    // socket 生命周期
    // =======================================================

    // 使用已有 pal_sock_t 创建 async socket
    anet_socket_t* anet_socket_create(anet_palsock_t sock);

    // 关闭（异步安全，可在任意时刻调用）
    void anet_socket_close(anet_socket_t *s);

    // 获取底层 socket
    anet_palsock_t anet_socket_native(anet_socket_t *s);


    // =======================================================
    // 单次异步 IO（一个操作 = 一个 future）
    // =======================================================

    // connect（完成或失败）
    future_t* anet_socket_connect(anet_socket_t *s,
                                   const struct sockaddr *addr,
                                   int addrlen);

    // accept（返回新的 anet_socket_t*）
    future_t* anet_socket_accept(anet_listener_t *listener);

    // recv（一次，可能部分，返回 size_t）
    // 返回 0 表示对端关闭
    future_t* anet_socket_recv(anet_socket_t *s,
                                void *buf,
                                size_t len);

    // send（一次，可能部分，返回 size_t）
    future_t* anet_socket_send(anet_socket_t *s,
                                const void *buf,
                                size_t len);


    // =======================================================
    // listener
    // =======================================================

    anet_listener_t* anet_listener_create(anet_palsock_t listen_sock);

    void anet_listener_close(anet_listener_t *l);

#ifdef __cplusplus
}
#endif
