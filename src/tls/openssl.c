#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "tls.h"
#include "sock/future_socket.h"

#define TLS_IO_BUF 16384

/* ============================================================
 * 异步SSL结构体
 * ============================================================ */

struct async_ssl {
    SSL_CTX        *ctx;
    SSL            *ssl;
    BIO            *rbio;
    BIO            *wbio;
    async_socket_t *sock;
    int             closed;
};

/* ============================================================
 * 同步SSL结构体
 * ============================================================ */

struct sync_ssl {
    SSL_CTX       *ctx;
    SSL           *ssl;
    BIO           *rbio;
    BIO           *wbio;
    anet_palsock_t sock;
    int            closed;
};

/* ============================================================
 * helpers
 * ============================================================ */

typedef struct {
    future_t *fut;
    void     *data;
} done_future_helper_t;

static void done_future(loop_t *loop, void *userdata)
{
    (void)loop;
    done_future_helper_t *h = (done_future_helper_t*)userdata;
    future_done(h->fut, h->data);
    free(h);
}

static future_t* create_future_done(void *data)
{
    future_t *fut = future_create();
    if (!fut) return NULL;

    done_future_helper_t *h = calloc(1, sizeof(*h));
    if (!h) {
        future_destroy(fut);
        return NULL;
    }

    h->fut = fut;
    h->data = data;
    loop_call_soon(done_future, h);
    return fut;
}

/* ============================================================
 * BIO <-> socket glue
 * ============================================================ */

static future_t* flush_wbio(async_ssl_t *s, uint8_t *buf)
{
    int n = BIO_read(s->wbio, buf, TLS_IO_BUF);
    if (n <= 0) {
        return create_future_done((void*)0);
    }
    return async_socket_send(s->sock, buf, (size_t)n);
}

static future_t* feed_rbio(async_ssl_t *s, uint8_t *buf)
{
    return async_socket_recv(s->sock, buf, TLS_IO_BUF);
}

/* ============================================================
 * create / attach
 * ============================================================ */

async_ssl_t* async_ssl_create(async_ssl_role_t role,
                              const char *hostname)
{
    async_ssl_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    SSL_library_init();
    SSL_load_error_strings();

    s->ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(s->ctx, TLS1_2_VERSION);

    s->ssl  = SSL_new(s->ctx);
    s->rbio = BIO_new(BIO_s_mem());
    s->wbio = BIO_new(BIO_s_mem());

    SSL_set_bio(s->ssl, s->rbio, s->wbio);

    if (role == ASYNC_SSL_CLIENT) {
        SSL_set_connect_state(s->ssl);
        if (hostname) {
            SSL_set_tlsext_host_name(s->ssl, hostname);
        }
    } else {
        SSL_set_accept_state(s->ssl);
    }

    return s;
}

void async_ssl_attach_socket(async_ssl_t *ssl,
                             async_socket_t *sock)
{
    ssl->sock = sock;
}

/* ============================================================
 * handshake
 * ============================================================ */

task_t* task_arg(async_ssl_handshake_) {
    gen_dec_vars(
        async_ssl_t *ssl;
        future_t    *fut;
        uint8_t      buf[TLS_IO_BUF];
    );
    gen_begin(ctx);

    {
        async_ssl_t *in = (async_ssl_t*)arg;
        gen_var(ssl) = in;
        // handshake arg 不需要 free，因为是 ssl 指针，不是堆参数
    }

    while (1) {
        int r = SSL_do_handshake(gen_var(ssl)->ssl);
        if (r == 1) {
            gen_return((void*)0);
        }

        int err = SSL_get_error(gen_var(ssl)->ssl, r);

        if (err == SSL_ERROR_WANT_WRITE) {
            while (BIO_pending(gen_var(ssl)->wbio) > 0) {
                gen_var(fut) = flush_wbio(gen_var(ssl), gen_var(buf));
                gen_yield(gen_var(fut));
            }
            continue;
        }

        if (err == SSL_ERROR_WANT_READ) {
            gen_var(fut) = feed_rbio(gen_var(ssl), gen_var(buf));
            gen_yield(gen_var(fut));

            ssize_t n = (ssize_t)(intptr_t)future_result(gen_var(fut));
            if (n <= 0) {
                gen_return((void*)(intptr_t)-1);
            }

            BIO_write(gen_var(ssl)->rbio, gen_var(buf), (int)n);
            continue;
        }

        gen_return((void*)(intptr_t)-1);
    }

    gen_end(NULL);
}

task_t* async_ssl_handshake(async_ssl_t *ssl)
{
    return async_ssl_handshake_(ssl);
}

/* ============================================================
 * read
 * ============================================================ */

typedef struct {
    async_ssl_t *ssl;
    void        *buf;
    size_t       len;
} ssl_read_arg_t;

task_t* task_arg(async_ssl_read_) {
    gen_dec_vars(
        ssl_read_arg_t a;
        future_t      *fut;
        uint8_t        tmp[TLS_IO_BUF];
    );
    gen_begin(ctx);

    {
        ssl_read_arg_t *in = (ssl_read_arg_t*)arg;
        gen_var(a) = *in; // 复制到 gen_dec_vars
        free(in);
    }

    while (1) {
        int n = SSL_read(gen_var(a).ssl->ssl,
                         gen_var(a).buf,
                         (int)gen_var(a).len);
        if (n > 0) {
            gen_return((void*)(intptr_t)n);
        }

        int err = SSL_get_error(gen_var(a).ssl->ssl, n);

        if (err == SSL_ERROR_WANT_WRITE) {
            while (BIO_pending(gen_var(a).ssl->wbio) > 0) {
                gen_var(fut) = flush_wbio(gen_var(a).ssl, gen_var(tmp));
                gen_yield(gen_var(fut));
            }
            continue;
        }

        if (err == SSL_ERROR_WANT_READ) {
            gen_var(fut) = feed_rbio(gen_var(a).ssl, gen_var(tmp));
            gen_yield(gen_var(fut));

            ssize_t r = (ssize_t)(intptr_t)future_result(gen_var(fut));
            if (r <= 0) {
                gen_return((void*)(intptr_t)-1);
            }

            BIO_write(gen_var(a).ssl->rbio, gen_var(tmp), (int)r);
            continue;
        }

        gen_return((void*)(intptr_t)-1);
    }

    gen_end(NULL);
}

task_t* async_ssl_read(async_ssl_t *ssl,
                       void *buf,
                       size_t len)
{
    ssl_read_arg_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
    a->ssl = ssl;
    a->buf = buf;
    a->len = len;

    return async_ssl_read_(a);
}

/* ============================================================
 * write
 * ============================================================ */

typedef struct {
    async_ssl_t  *ssl;
    const uint8_t *buf;
    size_t        len;
} ssl_write_arg_t;

task_t* task_arg(async_ssl_write_) {
    gen_dec_vars(
        ssl_write_arg_t a;
        size_t          off;
        future_t       *fut;
        uint8_t         tmp[TLS_IO_BUF];
    );
    gen_begin(ctx);

    {
        ssl_write_arg_t *in = (ssl_write_arg_t*)arg;
        gen_var(a) = *in; // 复制
        free(in);
    }

    gen_var(off) = 0;

    while (gen_var(off) < gen_var(a).len) {
        int n = SSL_write(gen_var(a).ssl->ssl,
                          gen_var(a).buf + gen_var(off),
                          (int)(gen_var(a).len - gen_var(off)));
        if (n > 0) {
            gen_var(off) += (size_t)n;

            while (BIO_pending(gen_var(a).ssl->wbio) > 0) {
                gen_var(fut) = flush_wbio(gen_var(a).ssl, gen_var(tmp));
                gen_yield(gen_var(fut));
            }
            continue;
        }

        int err = SSL_get_error(gen_var(a).ssl->ssl, n);

        if (err == SSL_ERROR_WANT_WRITE) {
            continue;
        }

        if (err == SSL_ERROR_WANT_READ) {
            gen_var(fut) = feed_rbio(gen_var(a).ssl, gen_var(tmp));
            gen_yield(gen_var(fut));

            ssize_t r = (ssize_t)(intptr_t)future_result(gen_var(fut));
            if (r <= 0) {
                gen_return((void*)(intptr_t)-1);
            }

            BIO_write(gen_var(a).ssl->rbio, gen_var(tmp), (int)r);
            continue;
        }

        gen_return((void*)(intptr_t)-1);
    }

    gen_return((void*)0);
    gen_end(NULL);
}

task_t* async_ssl_write(async_ssl_t *ssl,
                        const void *buf,
                        size_t len)
{
    ssl_write_arg_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
    a->ssl = ssl;
    a->buf = (const uint8_t*)buf;
    a->len = len;

    return async_ssl_write_(a);
}

/* ============================================================
 * close
 * ============================================================ */

task_t* task_arg(async_ssl_close_) {
    gen_dec_vars(
        async_ssl_t *ssl;
        future_t    *fut;
        uint8_t      buf[TLS_IO_BUF];
    );
    gen_begin(ctx);

    {
        async_ssl_t *in = (async_ssl_t*)arg;
        gen_var(ssl) = in;
    }

    SSL_shutdown(gen_var(ssl)->ssl);

    while (BIO_pending(gen_var(ssl)->wbio) > 0) {
        gen_var(fut) = flush_wbio(gen_var(ssl), gen_var(buf));
        gen_yield(gen_var(fut));
    }

    gen_var(ssl)->closed = 1;
    gen_return((void*)0);

    gen_end(NULL);
}

task_t* async_ssl_close(async_ssl_t *ssl)
{
    return async_ssl_close_(ssl);
}

/* ============================================================
 * 同步SSL实现
 * ============================================================ */

/* ============================================================
 * helpers
 * ============================================================ */

static int sync_flush_wbio(sync_ssl_t *ssl) {
    uint8_t buf[TLS_IO_BUF];
    int pending = BIO_pending(ssl->wbio);
    if (pending <= 0) return 0;
    
    int to_read = pending > sizeof(buf) ? sizeof(buf) : pending;
    int n = BIO_read(ssl->wbio, buf, to_read);
    if (n <= 0) return 0;
    
    int sent = anet_palsock_send(ssl->sock, buf, n, 0);
    return (sent == n) ? 0 : -1;
}

static int sync_feed_rbio(sync_ssl_t *ssl) {
    uint8_t buf[TLS_IO_BUF];
    int n = anet_palsock_recv(ssl->sock, buf, sizeof(buf), 0);
    if (n <= 0) return n;
    
    return BIO_write(ssl->rbio, buf, n);
}

/* ============================================================
 * create / attach
 * ============================================================ */

sync_ssl_t* sync_ssl_create(sync_ssl_role_t role, const char *hostname) {
    sync_ssl_t *ssl = calloc(1, sizeof(*ssl));
    if (!ssl) return NULL;

    SSL_library_init();
    SSL_load_error_strings();

    ssl->ctx = SSL_CTX_new(TLS_method());
    if (!ssl->ctx) {
        free(ssl);
        return NULL;
    }
    
    SSL_CTX_set_min_proto_version(ssl->ctx, TLS1_2_VERSION);

    ssl->ssl = SSL_new(ssl->ctx);
    if (!ssl->ssl) {
        SSL_CTX_free(ssl->ctx);
        free(ssl);
        return NULL;
    }
    
    ssl->rbio = BIO_new(BIO_s_mem());
    ssl->wbio = BIO_new(BIO_s_mem());
    if (!ssl->rbio || !ssl->wbio) {
        if (ssl->rbio) BIO_free(ssl->rbio);
        if (ssl->wbio) BIO_free(ssl->wbio);
        SSL_free(ssl->ssl);
        SSL_CTX_free(ssl->ctx);
        free(ssl);
        return NULL;
    }

    SSL_set_bio(ssl->ssl, ssl->rbio, ssl->wbio);

    if (role == SYNC_SSL_CLIENT) {
        SSL_set_connect_state(ssl->ssl);
        if (hostname) {
            SSL_set_tlsext_host_name(ssl->ssl, hostname);
        }
    } else {
        SSL_set_accept_state(ssl->ssl);
    }

    ssl->sock = -1;
    ssl->closed = 0;
    return ssl;
}

void sync_ssl_attach_socket(sync_ssl_t *ssl, anet_palsock_t sock) {
    ssl->sock = sock;
}

/* ============================================================
 * handshake
 * ============================================================ */

int sync_ssl_handshake(sync_ssl_t *ssl) {
    if (!ssl || !anet_palsock_is_valid(ssl->sock)) {
        return -1;
    }

    while (1) {
        int r = SSL_do_handshake(ssl->ssl);
        if (r == 1) return 0; // 成功

        int err = SSL_get_error(ssl->ssl, r);
        
        if (err == SSL_ERROR_WANT_WRITE) {
            if (sync_flush_wbio(ssl) != 0) return -1;
            continue;
        }
        
        if (err == SSL_ERROR_WANT_READ) {
            int n = sync_feed_rbio(ssl);
            if (n <= 0) return -1;
            continue;
        }
        
        return -1; // 其他错误
    }
}

/* ============================================================
 * read
 * ============================================================ */

int sync_ssl_read(sync_ssl_t *ssl, void *buf, size_t len) {
    if (!ssl || !buf || len == 0 || sync_ssl_is_closed(ssl)) {
        return -1;
    }

    while (1) {
        int n = SSL_read(ssl->ssl, buf, (int)len);
        if (n > 0) return n;

        int err = SSL_get_error(ssl->ssl, n);
        
        if (err == SSL_ERROR_WANT_WRITE) {
            if (sync_flush_wbio(ssl) != 0) return -1;
            continue;
        }
        
        if (err == SSL_ERROR_WANT_READ) {
            int r = sync_feed_rbio(ssl);
            if (r <= 0) return -1;
            continue;
        }
        
        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0; // 对端关闭连接
        }
        
        return -1;
    }
}

/* ============================================================
 * write
 * ============================================================ */

int sync_ssl_write(sync_ssl_t *ssl, const void *buf, size_t len) {
    if (!ssl || !buf || len == 0 || sync_ssl_is_closed(ssl)) {
        return -1;
    }

    size_t offset = 0;
    
    while (offset < len) {
        int n = SSL_write(ssl->ssl, (const uint8_t*)buf + offset, (int)(len - offset));
        if (n > 0) {
            offset += n;
            if (sync_flush_wbio(ssl) != 0) return -1;
            continue;
        }

        int err = SSL_get_error(ssl->ssl, n);
        
        if (err == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        
        if (err == SSL_ERROR_WANT_READ) {
            int r = sync_feed_rbio(ssl);
            if (r <= 0) return -1;
            continue;
        }
        
        return -1;
    }
    
    return 0;
}

/* ============================================================
 * close
 * ============================================================ */

void sync_ssl_close(sync_ssl_t *ssl) {
    if (!ssl || ssl->closed) return;
    
    SSL_shutdown(ssl->ssl);
    sync_flush_wbio(ssl);
    ssl->closed = 1;
}

int sync_ssl_is_closed(sync_ssl_t *ssl) {
    return ssl ? ssl->closed : 1;
}

/* ============================================================
 * destroy
 * ============================================================ */

void sync_ssl_destroy(sync_ssl_t *ssl) {
    if (!ssl) return;
    
    if (!ssl->closed) {
        sync_ssl_close(ssl);
    }
    
    SSL_free(ssl->ssl);
    SSL_CTX_free(ssl->ctx);
    free(ssl);
}
