#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "tls.h"
#include "sock/future_socket.h"

#define TLS_IO_BUF 16384

/* ============================================================
 * common helpers
 * ============================================================ */

static int bio_write_all(BIO *b, const uint8_t *buf, int len) {
    int off = 0;
    while (off < len) {
        int n = BIO_write(b, buf + off, len - off);
        if (n <= 0) return -1;
        off += n;
    }
    return off;
}

/* ============================================================
 * async SSL
 * ============================================================ */

struct async_ssl {
    SSL_CTX        *ctx;
    SSL            *ssl;
    BIO            *rbio;
    BIO            *wbio;
    async_socket_t *sock;
    int             closed;
};

typedef struct future_done_data_s {
    future_t *fut;
    void *data;
} future_done_data_t;

static void future_set_result(loop_t *_, void* userdata) {
    future_done_data_t *arg = userdata;
    future_done(arg->fut, arg->data);
    free(arg);
}

static future_t *future_done_value(void *data) {
    future_t *fut = future_create();
    if (!fut) return NULL;
    future_done_data_t *arg = calloc(1, sizeof(future_done_data_t));
    if (!arg) {
        future_destroy(fut);
        return NULL;
    }
    arg->data = data;
    arg->fut = fut;
    loop_call_soon(future_set_result, arg);
    return fut;
}

/* ------------------------------------------------------------
 * async BIO <-> socket glue
 * ------------------------------------------------------------ */

static future_t* async_flush_wbio(async_ssl_t *s, uint8_t *buf) {
    int n = BIO_read(s->wbio, buf, TLS_IO_BUF);
    if (n <= 0) {
        return future_done_value((void*)0);
    }
    return async_socket_send(s->sock, buf, (size_t)n);
}

static future_t* async_feed_rbio(async_ssl_t *s, uint8_t *buf) {
    return async_socket_recv(s->sock, buf, TLS_IO_BUF);
}

/* ------------------------------------------------------------
 * async create / attach
 * ------------------------------------------------------------ */

async_ssl_t* async_ssl_create(async_ssl_role_t role,
                              const char *hostname) {
    async_ssl_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(s->ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(s->ctx);

    s->ssl  = SSL_new(s->ctx);
    s->rbio = BIO_new(BIO_s_mem());
    s->wbio = BIO_new(BIO_s_mem());

    SSL_set_bio(s->ssl, s->rbio, s->wbio);

    if (role == ASYNC_SSL_CLIENT) {
        SSL_set_connect_state(s->ssl);
        if (hostname)
            SSL_set_tlsext_host_name(s->ssl, hostname);
    } else {
        SSL_set_accept_state(s->ssl);
    }

    return s;
}

void async_ssl_attach_socket(async_ssl_t *ssl,
                             async_socket_t *sock) {
    ssl->sock = sock;
}

/* ------------------------------------------------------------
 * async handshake
 * ------------------------------------------------------------ */

task_t* task_arg(async_ssl_handshake_) {
    gen_dec_vars(
        async_ssl_t *ssl;
        future_t    *fut;
        uint8_t      buf[TLS_IO_BUF];
    );
    gen_begin(ctx);

    gen_var(ssl) = (async_ssl_t*)arg;

    while (1) {
        int r = SSL_do_handshake(gen_var(ssl)->ssl);
        if (r == 1) {
            gen_return((void*)0);
        }

        int err = SSL_get_error(gen_var(ssl)->ssl, r);

        if (err == SSL_ERROR_WANT_WRITE) {
            while (BIO_pending(gen_var(ssl)->wbio) > 0) {
                gen_var(fut) = async_flush_wbio(gen_var(ssl), gen_var(buf));
                gen_yield(gen_var(fut));
            }
            continue;
        }

        if (err == SSL_ERROR_WANT_READ) {
            gen_var(fut) = async_feed_rbio(gen_var(ssl), gen_var(buf));
            gen_yield(gen_var(fut));

            ssize_t n = (ssize_t)(intptr_t)future_result(gen_var(fut));
            if (n <= 0) {
                gen_return((void*)(intptr_t)-1);
            }

            if (bio_write_all(gen_var(ssl)->rbio, gen_var(buf), (int)n) < 0) {
                gen_return((void*)(intptr_t)-1);
            }
            continue;
        }

        gen_return((void*)(intptr_t)-1);
    }

    gen_end(NULL);
}

task_t* async_ssl_handshake(async_ssl_t *ssl) {
    return async_ssl_handshake_(ssl);
}

/* ------------------------------------------------------------
 * async read
 * ------------------------------------------------------------ */

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

    gen_var(a) = *(ssl_read_arg_t*)arg;
    free(arg);

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
                gen_var(fut) = async_flush_wbio(gen_var(a).ssl, gen_var(tmp));
                gen_yield(gen_var(fut));
            }
            continue;
        }

        if (err == SSL_ERROR_WANT_READ) {
            gen_var(fut) = async_feed_rbio(gen_var(a).ssl, gen_var(tmp));
            gen_yield(gen_var(fut));

            ssize_t r = (ssize_t)(intptr_t)future_result(gen_var(fut));
            if (r <= 0) {
                gen_return((void*)(intptr_t)-1);
            }

            if (bio_write_all(gen_var(a).ssl->rbio, gen_var(tmp), (int)r) < 0) {
                gen_return((void*)(intptr_t)-1);
            }
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN) {
            gen_return((void*)0);
        }

        gen_return((void*)(intptr_t)-1);
    }

    gen_end(NULL);
}

task_t* async_ssl_read(async_ssl_t *ssl, void *buf, size_t len) {
    ssl_read_arg_t *a = malloc(sizeof(*a));
    a->ssl = ssl;
    a->buf = buf;
    a->len = len;
    return async_ssl_read_(a);
}

/* ------------------------------------------------------------
 * async write
 * ------------------------------------------------------------ */

typedef struct {
    async_ssl_t   *ssl;
    const uint8_t *buf;
    size_t         len;
} ssl_write_arg_t;

task_t* task_arg(async_ssl_write_) {
    gen_dec_vars(
        ssl_write_arg_t a;
        size_t          off;
        future_t       *fut;
        uint8_t         tmp[TLS_IO_BUF];
    );
    gen_begin(ctx);

    gen_var(a) = *(ssl_write_arg_t*)arg;
    free(arg);

    gen_var(off) = 0;

    while (gen_var(off) < gen_var(a).len) {
        int n = SSL_write(gen_var(a).ssl->ssl,
                          gen_var(a).buf + gen_var(off),
                          (int)(gen_var(a).len - gen_var(off)));
        if (n > 0) {
            gen_var(off) += (size_t)n;
            while (BIO_pending(gen_var(a).ssl->wbio) > 0) {
                gen_var(fut) = async_flush_wbio(gen_var(a).ssl, gen_var(tmp));
                gen_yield(gen_var(fut));
            }
            continue;
        }

        int err = SSL_get_error(gen_var(a).ssl->ssl, n);

        if (err == SSL_ERROR_WANT_WRITE)
            continue;

        if (err == SSL_ERROR_WANT_READ) {
            gen_var(fut) = async_feed_rbio(gen_var(a).ssl, gen_var(tmp));
            gen_yield(gen_var(fut));

            ssize_t r = (ssize_t)(intptr_t)future_result(gen_var(fut));
            if (r <= 0) {
                gen_return((void*)(intptr_t)-1);
            }

            if (bio_write_all(gen_var(a).ssl->rbio, gen_var(tmp), (int)r) < 0) {
                gen_return((void*)(intptr_t)-1);
            }
            continue;
        }

        gen_return((void*)(intptr_t)-1);
    }

    gen_return((void*)0);
    gen_end(NULL);
}

task_t* async_ssl_write(async_ssl_t *ssl,
                        const void *buf,
                        size_t len) {
    ssl_write_arg_t *a = malloc(sizeof(*a));
    a->ssl = ssl;
    a->buf = buf;
    a->len = len;
    return async_ssl_write_(a);
}

/* ------------------------------------------------------------
 * async close
 * ------------------------------------------------------------ */

task_t* task_arg(async_ssl_close_) {
    gen_dec_vars(
        async_ssl_t *ssl;
        future_t    *fut;
        uint8_t      buf[TLS_IO_BUF];
    );
    gen_begin(ctx);

    gen_var(ssl) = (async_ssl_t*)arg;

    SSL_shutdown(gen_var(ssl)->ssl);
    while (BIO_pending(gen_var(ssl)->wbio) > 0) {
        gen_var(fut) = async_flush_wbio(gen_var(ssl), gen_var(buf));
        gen_yield(gen_var(fut));
    }

    SSL_shutdown(gen_var(ssl)->ssl);
    while (BIO_pending(gen_var(ssl)->wbio) > 0) {
        gen_var(fut) = async_flush_wbio(gen_var(ssl), gen_var(buf));
        gen_yield(gen_var(fut));
    }

    gen_var(ssl)->closed = 1;
    gen_return((void*)0);
    gen_end(NULL);
}

task_t* async_ssl_close(async_ssl_t *ssl) {
    return async_ssl_close_(ssl);
}

/* ============================================================
 * sync SSL
 * ============================================================ */

struct sync_ssl {
    SSL_CTX       *ctx;
    SSL           *ssl;
    BIO           *rbio;
    BIO           *wbio;
    anet_palsock_t sock;
    int            closed;
};

/* ------------------------------------------------------------
 * sync helpers
 * ------------------------------------------------------------ */

static int sync_flush_wbio(sync_ssl_t *ssl) {
    uint8_t buf[TLS_IO_BUF];

    for (;;) {
        int pending = BIO_pending(ssl->wbio);
        if (pending <= 0)
            return 0;

        int n = BIO_read(ssl->wbio, buf, sizeof(buf));
        if (n < 0)
            return -1;
        if (n == 0)
            return 0;

        int off = 0;
        while (off < n) {
            int s = anet_palsock_send(
                ssl->sock, buf + off, n - off, 0);
            if (s <= 0)
                return -1;
            off += s;
        }
    }
}


static int sync_feed_rbio(sync_ssl_t *ssl) {
    uint8_t buf[TLS_IO_BUF];

    int n = anet_palsock_recv(ssl->sock, buf, sizeof(buf), 0);
    if (n > 0) {
        return bio_write_all(ssl->rbio, buf, n);
    }

    if (n == 0) {
        BIO_set_mem_eof_return(ssl->rbio, 0);
        return 0;
    }

    /* n < 0 */
    return -1;
}


/* ------------------------------------------------------------
 * sync create / attach
 * ------------------------------------------------------------ */

sync_ssl_t* sync_ssl_create(sync_ssl_role_t role,
                            const char *hostname) {
    sync_ssl_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(s->ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(s->ctx);
    SSL_CTX_load_verify_locations(s->ctx, "./cacert.pem", NULL);


    s->ssl  = SSL_new(s->ctx);
    s->rbio = BIO_new(BIO_s_mem());
    s->wbio = BIO_new(BIO_s_mem());
    BIO_set_write_buf_size(s->wbio, 16 * 1024);
    SSL_set_bio(s->ssl, s->rbio, s->wbio);

    if (role == SYNC_SSL_CLIENT) {
        SSL_set_connect_state(s->ssl);
        if (hostname) {
            SSL_set_tlsext_host_name(s->ssl, hostname);
            printf("Hostname: %s", hostname);
            // X509_VERIFY_PARAM *param = SSL_get0_param(s->ssl);
            // X509_VERIFY_PARAM_set1_host(param, hostname, 0);
        }

    } else {
        // need to load certificate file
        SSL_set_accept_state(s->ssl);
    }

    return s;
}

void sync_ssl_attach_socket(sync_ssl_t *ssl,
                            anet_palsock_t sock) {
    ssl->sock = sock;
}

/* ------------------------------------------------------------
 * sync handshake / read / write / close
 * ------------------------------------------------------------ */

int sync_ssl_handshake(sync_ssl_t *ssl) {
    for (;;) {
        int r = SSL_do_handshake(ssl->ssl);
        if (r == 1)
            return 0;

        int err = SSL_get_error(ssl->ssl, r);

        if (sync_flush_wbio(ssl) < 0)
            return -1;

        if (err == SSL_ERROR_WANT_WRITE) {
            continue;
        }

        if (err == SSL_ERROR_WANT_READ) {
            int n = sync_feed_rbio(ssl);
            if (n <= 0)
                return -1;
            continue;
        }

        long verify_result = SSL_get_verify_result(ssl->ssl);
        printf("verify_result = %ld\n", verify_result);
        return -1;
    }
}


int sync_ssl_read(sync_ssl_t *ssl, void *buf, size_t len) {
    for (;;) {
        int n = SSL_read(ssl->ssl, buf, (int)len);
        if (n > 0)
            return n;

        int err = SSL_get_error(ssl->ssl, n);

        if (err == SSL_ERROR_WANT_READ) {
            int r = sync_feed_rbio(ssl);
            if (r <= 0)
                return r; // 0 = EOF, <0 = error
            continue;
        }

        if (err == SSL_ERROR_WANT_WRITE) {
            if (sync_flush_wbio(ssl) < 0)
                return -1;
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN)
            return 0;

        return -1;
    }
}


int sync_ssl_write(sync_ssl_t *ssl,
                   const void *buf,
                   size_t len) {
    size_t off = 0;

    while (off < len) {
        int n = SSL_write(ssl->ssl,
                          (const uint8_t*)buf + off,
                          (int)(len - off));
        if (n > 0) {
            off += n;
            if (sync_flush_wbio(ssl) < 0)
                return -1;
            continue;
        }

        int err = SSL_get_error(ssl->ssl, n);

        if (err == SSL_ERROR_WANT_WRITE) {
            if (sync_flush_wbio(ssl) < 0)
                return -1;
            continue;
        }

        if (err == SSL_ERROR_WANT_READ) {
            int r = sync_feed_rbio(ssl);
            if (r <= 0)
                return -1;
            continue;
        }

        return -1;
    }
    return 0;
}


void sync_ssl_close(sync_ssl_t *ssl) {
    if (!ssl || ssl->closed)
        return;

    for (;;) {
        int r = SSL_shutdown(ssl->ssl);
        if (r == 1)
            break;

        if (r == 0) {
            sync_flush_wbio(ssl);
            continue;
        }

        int err = SSL_get_error(ssl->ssl, r);
        if (err == SSL_ERROR_WANT_WRITE) {
            if (sync_flush_wbio(ssl) < 0)
                break;
            continue;
        }
        if (err == SSL_ERROR_WANT_READ) {
            if (sync_feed_rbio(ssl) <= 0)
                break;
            continue;
        }
        break;
    }

    ssl->closed = 1;
}


void sync_ssl_destroy(sync_ssl_t *ssl) {
    if (!ssl) return;
    sync_ssl_close(ssl);
    SSL_free(ssl->ssl);
    SSL_CTX_free(ssl->ctx);
    free(ssl);
}
