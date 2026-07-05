/* ============================================================
 * wolfSSL TLS 后端
 *
 * 与 openssl.c 实现同一份 tls.h 契约,但用 wolfSSL 原生 API +
 * 自定义 IO 回调 (而非 OpenSSL 兼容层)。
 *
 * 设计:TLS 状态机与真实 socket IO 解耦——
 *   - wolfSSL 通过我们注册的 recv/send 回调读写两块内存缓冲:
 *       inbuf : 从 socket 收到、待喂给 wolfSSL 的密文
 *       outbuf: wolfSSL 产出、待发到 socket 的密文
 *   - recv 回调:从 inbuf 取;空则返回 WOLFSSL_CBIO_ERR_WANT_READ
 *   - send 回调:把密文追加进 outbuf,总是"接收"
 *   - 协程 pump: flush_out (把 outbuf 发到 async socket)、
 *                feed_in  (从 async socket 收一段进 inbuf)
 * 这套结构和 openssl.c 的 async_flush_wbio/async_feed_rbio 一一对应,
 * 握手/读/写/关闭的协程骨架照搬。
 * ============================================================ */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "tls.h"
#include "sock/future_socket.h"
#include "sock/stream.h"

#define TLS_IO_BUF 16384

/* ============================================================
 * 密文缓冲 (inbuf/outbuf 共用)
 * ============================================================ */

typedef struct {
    uint8_t *data;
    size_t   len;    /* 已用字节 */
    size_t   off;    /* 已消费偏移 (仅 inbuf 用) */
    size_t   cap;
} cbuf_t;

static int cbuf_append(cbuf_t *b, const uint8_t *src, size_t n) {
    if (b->len + n > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : TLS_IO_BUF;
        while (ncap < b->len + n) ncap *= 2;
        uint8_t *nd = realloc(b->data, ncap);
        if (!nd) return -1;
        b->data = nd;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

/* 消费掉已读部分,把剩余搬到头部 (避免 off 无限增长) */
static void cbuf_compact(cbuf_t *b) {
    if (b->off == 0) return;
    size_t remain = b->len - b->off;
    if (remain > 0) memmove(b->data, b->data + b->off, remain);
    b->len = remain;
    b->off = 0;
}

/* ============================================================
 * async SSL
 * ============================================================ */

struct async_ssl {
    WOLFSSL_CTX    *ctx;
    WOLFSSL        *ssl;
    cbuf_t          inbuf;    /* socket → wolfSSL 的密文 */
    cbuf_t          outbuf;   /* wolfSSL → socket 的密文 */
    async_socket_t *sock;
    int             closed;
};

/* ------------------------------------------------------------
 * wolfSSL IO 回调:只搬内存,真实 IO 由协程 pump 负责
 * ------------------------------------------------------------ */

static int async_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    async_ssl_t *s = (async_ssl_t*)ctx;
    size_t avail = s->inbuf.len - s->inbuf.off;
    if (avail == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;   /* 让上层去 feed_in */
    }
    size_t n = (size_t)sz < avail ? (size_t)sz : avail;
    memcpy(buf, s->inbuf.data + s->inbuf.off, n);
    s->inbuf.off += n;
    if (s->inbuf.off == s->inbuf.len) cbuf_compact(&s->inbuf);
    return (int)n;
}

static int async_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    async_ssl_t *s = (async_ssl_t*)ctx;
    if (sz <= 0) return 0;
    if (cbuf_append(&s->outbuf, (const uint8_t*)buf, (size_t)sz) != 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return sz;   /* 全部接收;真正发送在 flush_out */
}

/* ------------------------------------------------------------
 * async BIO <-> socket glue (对应 openssl.c 的 flush_wbio/feed_rbio)
 * ------------------------------------------------------------ */

/* 把 outbuf 里的密文全部发到 async socket。发完清空 outbuf。返回 >=0 成功,-1 失败。 */
task_t* task_arg(async_flush_out) {
    gen_dec_vars(
        async_ssl_t *ssl;
        future_t    *fut;
        size_t       off;
        int          s;
    );
    gen_begin(ctx)

    gen_var(ssl) = arg;
    gen_var(off) = 0;

    while (gen_var(off) < gen_var(ssl)->outbuf.len) {
        gen_var(fut) = async_socket_send(
            gen_var(ssl)->sock,
            (const char*)gen_var(ssl)->outbuf.data + gen_var(off),
            gen_var(ssl)->outbuf.len - gen_var(off)
        );
        gen_yield(gen_var(fut));
        gen_var(s) = (int)anet_code_of(future_result(gen_var(fut)));
        if (gen_var(s) <= 0) {
            gen_return(anet_res_code(-1));
        }
        gen_var(off) += (size_t)gen_var(s);
    }

    gen_var(ssl)->outbuf.len = 0;   /* 全部发出,清空 */
    gen_end(anet_res_code(0));
}

/* 从 async socket 收一段密文进 inbuf。返回 >0 字节数,0 EOF,-1 错误。 */
task_t* task_arg(async_feed_in) {
    gen_dec_vars(
        async_ssl_t *ssl;
        char         buf[TLS_IO_BUF];
        future_t    *fut;
        int          n;
    );
    gen_begin(ctx)

    gen_var(ssl) = arg;

    gen_var(fut) = async_socket_recv(gen_var(ssl)->sock, gen_var(buf), sizeof(gen_var(buf)));
    gen_yield(gen_var(fut));
    gen_var(n) = (int)anet_code_of(future_result(gen_var(fut)));

    if (gen_var(n) > 0) {
        int ret = cbuf_append(&gen_var(ssl)->inbuf, (const uint8_t*)gen_var(buf), (size_t)gen_var(n));
        gen_return(anet_res_code(ret < 0 ? -1 : gen_var(n)));
    }
    if (gen_var(n) == 0) {
        gen_return(anet_res_code(0));   /* EOF */
    }
    gen_end(anet_res_code(-1));
}

/* ------------------------------------------------------------
 * async create / attach
 * ------------------------------------------------------------ */

async_ssl_t* async_ssl_create(async_ssl_role_t role,
                              const char *hostname) {
    async_ssl_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    WOLFSSL_METHOD *method = (role == ASYNC_SSL_CLIENT)
        ? wolfTLS_client_method()
        : wolfTLS_server_method();
    s->ctx = wolfSSL_CTX_new(method);
    if (!s->ctx) { free(s); return NULL; }

    wolfSSL_CTX_SetIORecv(s->ctx, async_recv_cb);
    wolfSSL_CTX_SetIOSend(s->ctx, async_send_cb);
    wolfSSL_CTX_SetMinVersion(s->ctx, WOLFSSL_TLSV1_2);

    if (role == ASYNC_SSL_CLIENT) {
        wolfSSL_CTX_set_verify(s->ctx, WOLFSSL_VERIFY_PEER, NULL);
        if (wolfSSL_CTX_load_verify_locations(s->ctx, "./cacert.pem", NULL)
                != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(s->ctx); free(s); return NULL;
        }
    }

    s->ssl = wolfSSL_new(s->ctx);
    if (!s->ssl) { wolfSSL_CTX_free(s->ctx); free(s); return NULL; }

    wolfSSL_SetIOReadCtx(s->ssl, s);
    wolfSSL_SetIOWriteCtx(s->ssl, s);

    if (role == ASYNC_SSL_CLIENT && hostname) {
        wolfSSL_UseSNI(s->ssl, WOLFSSL_SNI_HOST_NAME, hostname, (unsigned short)strlen(hostname));
        /* loopback 测试证书用 IP:127.0.0.1 的 SAN;主机名是 IP 时按 IP 校验,
           否则按域名校验。 */
        if (hostname[0] >= '0' && hostname[0] <= '9') {
            wolfSSL_check_ip_address(s->ssl, hostname);
        } else {
            wolfSSL_check_domain_name(s->ssl, hostname);
        }
    }
    /* 服务端角色:wolfTLS_server_method() 建的 CTX 已是 accept 模式,无需额外设置。 */

    return s;
}

async_ssl_t* async_ssl_create_server(const char *cert_path,
                                     const char *key_path) {
    if (!cert_path || !key_path) return NULL;

    async_ssl_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->ctx = wolfSSL_CTX_new(wolfTLS_server_method());
    if (!s->ctx) { free(s); return NULL; }

    wolfSSL_CTX_SetIORecv(s->ctx, async_recv_cb);
    wolfSSL_CTX_SetIOSend(s->ctx, async_send_cb);
    wolfSSL_CTX_SetMinVersion(s->ctx, WOLFSSL_TLSV1_2);
    wolfSSL_CTX_set_verify(s->ctx, WOLFSSL_VERIFY_NONE, NULL);   /* 不校验客户端 */

    if (wolfSSL_CTX_use_certificate_chain_file(s->ctx, cert_path) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(s->ctx, key_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(s->ctx); free(s); return NULL;
    }

    s->ssl = wolfSSL_new(s->ctx);
    if (!s->ssl) { wolfSSL_CTX_free(s->ctx); free(s); return NULL; }

    wolfSSL_SetIOReadCtx(s->ssl, s);
    wolfSSL_SetIOWriteCtx(s->ssl, s);

    return s;
}

void async_ssl_attach_socket(async_ssl_t *ssl, async_socket_t *sock) {
    ssl->sock = sock;
}

/* ------------------------------------------------------------
 * async handshake
 * ------------------------------------------------------------ */

task_t* task_arg(async_ssl_handshake_) {
    gen_dec_vars(
        async_ssl_t *ssl;
        task_t      *task;
        int          err;
    );
    gen_begin(ctx);

    gen_var(ssl) = (async_ssl_t*)arg;

    while (1) {
        int r = wolfSSL_negotiate(gen_var(ssl)->ssl);
        if (r == WOLFSSL_SUCCESS) {
            /* 握手可能残留待发密文 (如 Finished),先冲出去 */
            gen_var(task) = async_flush_out(gen_var(ssl));
            gen_yield_from_task(gen_var(task));
            gen_return(anet_res_code(0));
        }

        gen_var(err) = wolfSSL_get_error(gen_var(ssl)->ssl, r);

        /* 无论如何先把 wolfSSL 已产出的密文发出去 */
        gen_var(task) = async_flush_out(gen_var(ssl));
        gen_yield_from_task(gen_var(task));
        if (anet_code_of(future_result(gen_var(task)->future)) < 0) {
            gen_return(anet_res_code(-1));
        }

        if (gen_var(err) == WOLFSSL_ERROR_WANT_WRITE) {
            continue;
        }
        if (gen_var(err) == WOLFSSL_ERROR_WANT_READ) {
            gen_var(task) = async_feed_in(gen_var(ssl));
            gen_yield_from_task(gen_var(task));
            if (anet_code_of(future_result(gen_var(task)->future)) <= 0) {
                gen_return(anet_res_code(-1));
            }
            continue;
        }
        gen_return(anet_res_code(-1));
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
        task_t        *task;
        int            err;
    );
    gen_begin(ctx);

    gen_var(a) = *(ssl_read_arg_t*)arg;
    free(arg);

    while (1) {
        int n = wolfSSL_read(gen_var(a).ssl->ssl, gen_var(a).buf, (int)gen_var(a).len);
        if (n > 0) {
            gen_return(anet_res_code(n));
        }

        gen_var(err) = wolfSSL_get_error(gen_var(a).ssl->ssl, n);

        if (gen_var(err) == WOLFSSL_ERROR_WANT_READ) {
            gen_var(task) = async_feed_in(gen_var(a).ssl);
            gen_yield_from_task(gen_var(task));
            if (anet_code_of(future_result(gen_var(task)->future)) <= 0) {
                gen_return(anet_res_code(-1));
            }
            continue;
        }
        if (gen_var(err) == WOLFSSL_ERROR_WANT_WRITE) {
            gen_var(task) = async_flush_out(gen_var(a).ssl);
            gen_yield_from_task(gen_var(task));
            if (anet_code_of(future_result(gen_var(task)->future)) < 0) {
                gen_return(anet_res_code(-1));
            }
            continue;
        }
        if (gen_var(err) == WOLFSSL_ERROR_ZERO_RETURN) {
            gen_return(anet_res_code(0));   /* 对端 close_notify */
        }
        gen_return(anet_res_code(-1));
    }

    gen_end(NULL);
}

task_t* async_ssl_read(async_ssl_t *ssl, void *buf, size_t len) {
    ssl_read_arg_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
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
        int             err;
        int             n;
        task_t         *task;
    );
    gen_begin(ctx);

    gen_var(a) = *(ssl_write_arg_t*)arg;
    free(arg);

    gen_var(off) = 0;

    while (gen_var(off) < gen_var(a).len) {
        gen_var(n) = wolfSSL_write(gen_var(a).ssl->ssl,
                                   gen_var(a).buf + gen_var(off),
                                   (int)(gen_var(a).len - gen_var(off)));
        if (gen_var(n) > 0) {
            gen_var(off) += (size_t)gen_var(n);
            gen_var(task) = async_flush_out(gen_var(a).ssl);
            gen_yield_from_task(gen_var(task));
            if (anet_code_of(future_result(gen_var(task)->future)) < 0) {
                gen_return(anet_res_code(-1));
            }
            continue;
        }

        gen_var(err) = wolfSSL_get_error(gen_var(a).ssl->ssl, gen_var(n));

        if (gen_var(err) == WOLFSSL_ERROR_WANT_WRITE) {
            gen_var(task) = async_flush_out(gen_var(a).ssl);
            gen_yield_from_task(gen_var(task));
            if (anet_code_of(future_result(gen_var(task)->future)) < 0) {
                gen_return(anet_res_code(-1));
            }
            continue;
        }
        if (gen_var(err) == WOLFSSL_ERROR_WANT_READ) {
            gen_var(task) = async_feed_in(gen_var(a).ssl);
            gen_yield_from_task(gen_var(task));
            if (anet_code_of(future_result(gen_var(task)->future)) <= 0) {
                gen_return(anet_res_code(-1));
            }
            continue;
        }
        if (gen_var(err) == WOLFSSL_ERROR_ZERO_RETURN) {
            gen_return(anet_res_code(0));
        }
        gen_return(anet_res_code(-1));
    }

    gen_end(anet_res_code((intptr_t)gen_var(a).len));
}

task_t* async_ssl_write(async_ssl_t *ssl, const void *buf, size_t len) {
    ssl_write_arg_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
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
        int          err;
        int          n;
        task_t      *task;
    );
    gen_begin(ctx);

    gen_var(ssl) = (async_ssl_t*)arg;

    for (;;) {
        gen_var(n) = wolfSSL_shutdown(gen_var(ssl)->ssl);
        /* 冲出 close_notify */
        gen_var(task) = async_flush_out(gen_var(ssl));
        gen_yield_from_task(gen_var(task));
        if (anet_code_of(future_result(gen_var(task)->future)) < 0) {
            break;
        }

        if (gen_var(n) == WOLFSSL_SUCCESS) break;

        gen_var(err) = wolfSSL_get_error(gen_var(ssl)->ssl, gen_var(n));
        if (gen_var(err) == WOLFSSL_ERROR_WANT_READ) {
            gen_var(task) = async_feed_in(gen_var(ssl));
            gen_yield_from_task(gen_var(task));
            if (anet_code_of(future_result(gen_var(task)->future)) <= 0) {
                break;
            }
            continue;
        }
        if (gen_var(err) == WOLFSSL_ERROR_WANT_WRITE) {
            continue;   /* 上面已 flush */
        }
        break;
    }

    gen_var(ssl)->closed = 1;
    gen_end(anet_res_code(0));
}

task_t* async_ssl_close(async_ssl_t *ssl) {
    return async_ssl_close_(ssl);
}

void async_ssl_destroy(async_ssl_t *ssl) {
    if (!ssl) return;
    wolfSSL_free(ssl->ssl);
    wolfSSL_CTX_free(ssl->ctx);
    free(ssl->inbuf.data);
    free(ssl->outbuf.data);
    /* attach 的 async socket 所有权归我们,释放。 */
    if (ssl->sock) {
        async_socket_close(ssl->sock);
        free(ssl->sock);
    }
    free(ssl);
}

int async_ssl_is_closed(async_ssl_t *ssl) {
    return ssl ? ssl->closed : 1;
}

/* ============================================================
 * sync SSL
 * ============================================================ */

struct sync_ssl {
    WOLFSSL_CTX   *ctx;
    WOLFSSL       *ssl;
    cbuf_t         inbuf;
    cbuf_t         outbuf;
    anet_palsock_t sock;
    int            closed;
};

/* sync 版 IO 回调:同样只搬内存,真实 IO 在 sync_flush_out/sync_feed_in。 */
static int sync_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    sync_ssl_t *s = (sync_ssl_t*)ctx;
    size_t avail = s->inbuf.len - s->inbuf.off;
    if (avail == 0) return WOLFSSL_CBIO_ERR_WANT_READ;
    size_t n = (size_t)sz < avail ? (size_t)sz : avail;
    memcpy(buf, s->inbuf.data + s->inbuf.off, n);
    s->inbuf.off += n;
    if (s->inbuf.off == s->inbuf.len) cbuf_compact(&s->inbuf);
    return (int)n;
}

static int sync_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    sync_ssl_t *s = (sync_ssl_t*)ctx;
    if (sz <= 0) return 0;
    if (cbuf_append(&s->outbuf, (const uint8_t*)buf, (size_t)sz) != 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return sz;
}

static int sync_flush_out(sync_ssl_t *ssl) {
    size_t off = 0;
    while (off < ssl->outbuf.len) {
        int s = anet_palsock_send(ssl->sock,
                                  (const char*)ssl->outbuf.data + off,
                                  ssl->outbuf.len - off, 0);
        if (s <= 0) return -1;
        off += (size_t)s;
    }
    ssl->outbuf.len = 0;
    return 0;
}

static int sync_feed_in(sync_ssl_t *ssl) {
    char buf[TLS_IO_BUF];
    int n = anet_palsock_recv(ssl->sock, buf, sizeof(buf), 0);
    if (n > 0) {
        return cbuf_append(&ssl->inbuf, (const uint8_t*)buf, (size_t)n) < 0 ? -1 : n;
    }
    if (n == 0) return 0;   /* EOF */
    return -1;
}

sync_ssl_t* sync_ssl_create(sync_ssl_role_t role, const char *hostname) {
    sync_ssl_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    WOLFSSL_METHOD *method = (role == SYNC_SSL_CLIENT)
        ? wolfTLS_client_method()
        : wolfTLS_server_method();
    s->ctx = wolfSSL_CTX_new(method);
    if (!s->ctx) { free(s); return NULL; }

    wolfSSL_CTX_SetIORecv(s->ctx, sync_recv_cb);
    wolfSSL_CTX_SetIOSend(s->ctx, sync_send_cb);
    wolfSSL_CTX_SetMinVersion(s->ctx, WOLFSSL_TLSV1_2);

    if (role == SYNC_SSL_CLIENT) {
        wolfSSL_CTX_set_verify(s->ctx, WOLFSSL_VERIFY_PEER, NULL);
        if (wolfSSL_CTX_load_verify_locations(s->ctx, "./cacert.pem", NULL)
                != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(s->ctx); free(s); return NULL;
        }
    }

    s->ssl = wolfSSL_new(s->ctx);
    if (!s->ssl) { wolfSSL_CTX_free(s->ctx); free(s); return NULL; }

    wolfSSL_SetIOReadCtx(s->ssl, s);
    wolfSSL_SetIOWriteCtx(s->ssl, s);

    if (role == SYNC_SSL_CLIENT && hostname) {
        wolfSSL_UseSNI(s->ssl, WOLFSSL_SNI_HOST_NAME, hostname, (unsigned short)strlen(hostname));
        if (hostname[0] >= '0' && hostname[0] <= '9') {
            wolfSSL_check_ip_address(s->ssl, hostname);
        } else {
            wolfSSL_check_domain_name(s->ssl, hostname);
        }
    }
    /* 服务端 method 已是 accept 模式。 */

    return s;
}

void sync_ssl_attach_socket(sync_ssl_t *ssl, anet_palsock_t sock) {
    ssl->sock = sock;
}

int sync_ssl_handshake(sync_ssl_t *ssl) {
    for (;;) {
        int r = wolfSSL_negotiate(ssl->ssl);
        if (r == WOLFSSL_SUCCESS) {
            return sync_flush_out(ssl) < 0 ? -1 : 0;
        }
        int err = wolfSSL_get_error(ssl->ssl, r);
        if (sync_flush_out(ssl) < 0) return -1;
        if (err == WOLFSSL_ERROR_WANT_WRITE) continue;
        if (err == WOLFSSL_ERROR_WANT_READ) {
            if (sync_feed_in(ssl) <= 0) return -1;
            continue;
        }
        return -1;
    }
}

int sync_ssl_read(sync_ssl_t *ssl, void *buf, size_t len) {
    for (;;) {
        int n = wolfSSL_read(ssl->ssl, buf, (int)len);
        if (n > 0) return n;
        int err = wolfSSL_get_error(ssl->ssl, n);
        if (err == WOLFSSL_ERROR_WANT_READ) {
            int r = sync_feed_in(ssl);
            if (r <= 0) return r;   /* 0=EOF, <0=err */
            continue;
        }
        if (err == WOLFSSL_ERROR_WANT_WRITE) {
            if (sync_flush_out(ssl) < 0) return -1;
            continue;
        }
        if (err == WOLFSSL_ERROR_ZERO_RETURN) return 0;
        return -1;
    }
}

int sync_ssl_write(sync_ssl_t *ssl, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = wolfSSL_write(ssl->ssl, (const uint8_t*)buf + off, (int)(len - off));
        if (n > 0) {
            off += (size_t)n;
            if (sync_flush_out(ssl) < 0) return -1;
            continue;
        }
        int err = wolfSSL_get_error(ssl->ssl, n);
        if (err == WOLFSSL_ERROR_WANT_WRITE) {
            if (sync_flush_out(ssl) < 0) return -1;
            continue;
        }
        if (err == WOLFSSL_ERROR_WANT_READ) {
            if (sync_feed_in(ssl) <= 0) return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

void sync_ssl_close(sync_ssl_t *ssl) {
    if (!ssl || ssl->closed) return;
    for (;;) {
        int r = wolfSSL_shutdown(ssl->ssl);
        if (sync_flush_out(ssl) < 0) break;
        if (r == WOLFSSL_SUCCESS) break;
        int err = wolfSSL_get_error(ssl->ssl, r);
        if (err == WOLFSSL_ERROR_WANT_READ) {
            if (sync_feed_in(ssl) <= 0) break;
            continue;
        }
        if (err == WOLFSSL_ERROR_WANT_WRITE) continue;
        break;
    }
    ssl->closed = 1;
}

void sync_ssl_destroy(sync_ssl_t *ssl) {
    if (!ssl) return;
    sync_ssl_close(ssl);
    wolfSSL_free(ssl->ssl);
    wolfSSL_CTX_free(ssl->ctx);
    free(ssl->inbuf.data);
    free(ssl->outbuf.data);
    free(ssl);
}

int sync_ssl_is_closed(sync_ssl_t *ssl) {
    return ssl ? ssl->closed : 1;
}

/* ============================================================
 * 后端无关 crypto 原语 (wolfSSL 实现)
 * ============================================================ */

#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>

/* wolfCrypt 需要先 wolfCrypt_Init 才能安全用 RNG/SHA。走 TLS 时 wolfSSL_new
   会间接初始化,但纯明文 WS 握手 (只调下面两个 crypto helper) 从不创建 SSL
   对象,于是 wc_InitRng 在未初始化的 wolfCrypt 上跑——在 Windows 的
   CryptAcquireContext 种子路径下会卡死。这里做一次性 guard 兜底。
   (单线程 loop 模型,无需加锁。) */
static int g_wc_inited = 0;
static void ensure_wc_init(void) {
    if (!g_wc_inited) {
        wolfCrypt_Init();
        g_wc_inited = 1;
    }
}

int anet_tls_rand_bytes(unsigned char *buf, size_t len) {
    ensure_wc_init();
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) return -1;
    int rc = wc_RNG_GenerateBlock(&rng, buf, (word32)len) == 0 ? 0 : -1;
    wc_FreeRng(&rng);
    return rc;
}

int anet_tls_sha1(const unsigned char *data, size_t len, unsigned char *out) {
    ensure_wc_init();
    wc_Sha sha;
    if (wc_InitSha(&sha) != 0) return -1;
    int rc = -1;
    if (wc_ShaUpdate(&sha, data, (word32)len) == 0 &&
        wc_ShaFinal(&sha, out) == 0) {
        rc = 0;
    }
    wc_ShaFree(&sha);
    return rc;
}
