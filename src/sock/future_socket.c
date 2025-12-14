#include "sock/future_socket.h"
#include <libcoro.h>
#include <stdlib.h>
#include <string.h>

// =======================================================
// 内部结构
// =======================================================

struct async_socket {
    anet_palsock_t   sock;      // native socket / handle
    int              closed;
};

struct async_listener {
    anet_palsock_t   sock;
    int              closed;
};

// 每个 IO 操作对应一个 context
typedef struct async_op_ctx {
    future_t *future;
    void     *extra;   // buffer / socket 等
} async_op_ctx_t;


// =======================================================
// recv / send / connect 回调
// =======================================================

static void async_io_cb(loop_t *loop,
                        void *userdata,
                        loop_op_type_t type,
                        int err,
                        unsigned long bytes,
                        recv_data_t *rdata)
{
    async_op_ctx_t *ctx = (async_op_ctx_t*)userdata;

    if (err != 0) {
        future_reject(ctx->future, (void*) err);
        return;
    }

    // bytes 对 recv/send 都成立
    future_done(ctx->future, (void*) bytes);
}


// =======================================================
// accept 回调
// =======================================================

static void async_accept_cb(loop_t *loop,
                            void *userdata,
                            loop_op_type_t type,
                            int err,
                            unsigned long bytes,
                            recv_data_t *rdata)
{
    async_op_ctx_t *ctx = (async_op_ctx_t*)userdata;

    if (err != 0) {
        future_reject(ctx->future, (void*) err);
        return;
    }

    async_socket_t *client = (async_socket_t*)ctx->extra;

    // bind 新 socket 到 loop
    loop_bind_handle((void*)client->sock);

    future_done(ctx->future, client);
    free(ctx);
}


// =======================================================
// socket 生命周期
// =======================================================

async_socket_t* async_socket_create(anet_palsock_t sock)
{
    async_socket_t *s = calloc(1, sizeof(*s));
    s->sock   = sock;
    s->closed = 0;

    anet_palsock_set_nonblocking(s->sock, 1);
    loop_bind_handle((void*)s->sock);
    return s;
}

void async_socket_close(async_socket_t *s)
{
    if (!s || s->closed)
        return;

    s->closed = 1;
    anet_palsock_close(s->sock);
}

anet_palsock_t async_socket_native(async_socket_t *s)
{
    return s->sock;
}


// =======================================================
// 单次 async IO
// =======================================================

future_t* async_socket_recv(async_socket_t *s,
                            void *buf,
                            size_t len)
{
    async_op_ctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->future = future_create();

    loop_op_id_t id = loop_post_recv(
        (void*)s->sock,
        (char*)buf,
        (unsigned long)len,
        async_io_cb,
        ctx
    );

    if (id == LOOP_INVALID_OP_ID) {
        future_reject(ctx->future, (void*) -1);
        free(ctx);
    }

    return ctx->future;
}

future_t* async_socket_send(async_socket_t *s,
                            const void *buf,
                            size_t len)
{
    async_op_ctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->future = future_create();

    loop_op_id_t id = loop_post_send(
        (void*)s->sock,
        (const char*)buf,
        (unsigned long)len,
        async_io_cb,
        ctx
    );

    if (id == LOOP_INVALID_OP_ID) {
        future_reject(ctx->future, (void*) -1);
        free(ctx);
    }

    return ctx->future;
}

future_t* async_socket_connect(async_socket_t *s,
                               const struct sockaddr *addr,
                               int addrlen)
{
    async_op_ctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->future = future_create();

    loop_op_id_t id = loop_connect_async(
        (void*)s->sock,
        addr,
        addrlen,
        async_io_cb,
        ctx
    );

    if (id == LOOP_INVALID_OP_ID) {
        future_reject(ctx->future, (void*) -1);
        free(ctx);
    }

    return ctx->future;
}


// =======================================================
// listener
// =======================================================

async_listener_t* async_listener_create(anet_palsock_t listen_sock)
{
    async_listener_t *l = calloc(1, sizeof(*l));
    l->sock   = listen_sock;
    l->closed = 0;

    loop_bind_handle((void*)l->sock);
    return l;
}

void async_listener_close(async_listener_t *l)
{
    if (!l || l->closed)
        return;

    l->closed = 1;
    anet_palsock_close(l->sock);
}


// =======================================================
// accept
// =======================================================

future_t* async_socket_accept(async_listener_t *listener)
{
    async_op_ctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->future = future_create();

    async_socket_t *client = calloc(1, sizeof(*client));

    ctx->extra = client;

    loop_op_id_t id = loop_accept_async(
        (void*)listener->sock,
        (void**)&client->sock,
        async_accept_cb,
        ctx
    );

    if (id == LOOP_INVALID_OP_ID) {
        future_reject(ctx->future, (void*) -1);
        free(client);
        free(ctx);
    }

    return ctx->future;
}
