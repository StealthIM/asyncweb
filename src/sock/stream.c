#include "sock/stream.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define STREAM_INTERNAL_BUF 4096

struct async_stream {
    async_socket_t *sock;
    async_ssl_t    *ssl;
    uint8_t         read_buf[STREAM_INTERNAL_BUF];
    size_t          read_buf_len;
    size_t          read_buf_off;
};

/* ==============================
 * 创建 stream
 * ============================== */

async_stream_t* async_stream_from_socket(async_socket_t *sock)
{
    async_stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->sock = sock;
    return s;
}

async_stream_t* async_stream_from_ssl(async_ssl_t *ssl)
{
    async_stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->ssl = ssl;
    return s;
}

/* ==============================
 * 关闭 stream
 * ============================== */

task_t* task_arg(async_stream_close_) {
    gen_dec_vars(
        async_stream_t *s;
    );
    gen_begin(ctx);

    {
        async_stream_t *in = (async_stream_t*)arg;
        gen_var(s) = in;
    }

    if (gen_var(s)->ssl) {
        gen_yield_from_task(async_ssl_close(gen_var(s)->ssl));
    }

    // no explicit close for sock needed, assume managed externally
    free(gen_var(s));
    gen_end(0);
}

task_t* async_stream_close(async_stream_t *s)
{
    return async_stream_close_(s);
}

/* ==============================
 * read_exactly
 * ============================== */

typedef struct {
    async_stream_t *s;
    void           *buf;
    size_t          len;
} stream_read_arg_t;

task_t* task_arg(async_stream_read_exactly_) {
    gen_dec_vars(
        stream_read_arg_t arg_copy;
        size_t            total_read;
        future_t         *fut;
        task_t           *task;
    );
    gen_begin(ctx);

    {
        stream_read_arg_t *in = (stream_read_arg_t*)arg;
        gen_var(arg_copy) = *in;
        free(in);
    }
    gen_var(total_read) = 0;

    while (gen_var(total_read) < gen_var(arg_copy.len)) {
        gen_var(task) = async_stream_read(gen_var(arg_copy).s, 1, gen_var(arg_copy).buf + gen_var(total_read));
        gen_yield_from_task(gen_var(task));

        int result = (int)future_result(gen_var(task)->future);
        if (result <= 0) {
            gen_return(-1);
        }
        gen_var(total_read) += result;
    }

    gen_return(0);
    gen_end(NULL);
}

task_t *async_stream_read_exactly(async_stream_t *s,
                                  size_t len,
                                  void *buf)
{
    stream_read_arg_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
    a->s = s;
    a->buf = buf;
    a->len = len;
    return async_stream_read_exactly_(a);
}

/* ==============================
 * read (single read operation)
 * ============================== */

typedef struct {
    async_stream_t *s;
    void           *buf;
    size_t          max_len;
} stream_read_single_arg_t;

task_t* task_arg(async_stream_read_) {
    gen_dec_vars(
        stream_read_single_arg_t arg_copy;
        future_t         *fut;
        task_t           *task;
        int               n;
    );
    gen_begin(ctx);

    {
        stream_read_single_arg_t *in = (stream_read_single_arg_t*)arg;
        gen_var(arg_copy) = *in;
        free(in);
    }

    // 如果有缓冲数据，先返回缓冲数据
    if (gen_var(arg_copy.s)->read_buf_off < gen_var(arg_copy.s)->read_buf_len) {
        size_t avail = gen_var(arg_copy.s)->read_buf_len - gen_var(arg_copy.s)->read_buf_off;
        size_t to_copy = avail < gen_var(arg_copy.max_len) ? avail : gen_var(arg_copy.max_len);
        
        memcpy(gen_var(arg_copy.buf),
               gen_var(arg_copy.s)->read_buf + gen_var(arg_copy.s)->read_buf_off,
               to_copy);
        gen_var(arg_copy.s)->read_buf_off += to_copy;
        
        gen_return((void*)(intptr_t)to_copy);
    }

    // 没有缓冲数据，直接从socket读取
    if (gen_var(arg_copy.s)->ssl) {
        gen_var(task) = async_ssl_read(gen_var(arg_copy.s)->ssl, gen_var(arg_copy.buf), gen_var(arg_copy.max_len));
        gen_yield_from_task(gen_var(task));
        gen_var(n) = (int)(intptr_t)future_result(gen_var(task)->future);
    } else {
        gen_var(fut) = async_socket_recv(gen_var(arg_copy.s)->sock, gen_var(arg_copy.buf), gen_var(arg_copy.max_len));
        gen_yield(gen_var(fut));
        gen_var(n) = (int)(intptr_t)future_result(gen_var(fut));
    }

    if (gen_var(n) <= 0) {
        gen_return((void*)-1);
    }

    gen_end((void*)(intptr_t)gen_var(n));
}

task_t *async_stream_read(async_stream_t *s, size_t max_len, void *buf)
{
    stream_read_single_arg_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
    a->s = s;
    a->buf = buf;
    a->max_len = max_len;
    return async_stream_read_(a);
}

/* ==============================
 * write_all
 * ============================== */

typedef struct {
    async_stream_t *s;
    const void     *buf;
    size_t          len;
} stream_write_arg_t;

task_t* task_arg(async_stream_write_all_) {
    gen_dec_vars(
        stream_write_arg_t arg_copy;
        size_t off;
        future_t *fut;
        task_t *task;
        ssize_t n;
    );
    gen_begin(ctx);

    {
        stream_write_arg_t *in = (stream_write_arg_t*)arg;
        gen_var(arg_copy) = *in;
        free(in);
    }

    gen_var(off) = 0;

    while (gen_var(off) < gen_var(arg_copy.len)) {
        size_t remain = gen_var(arg_copy.len) - gen_var(off);

        if (gen_var(arg_copy.s)->ssl) {
            gen_var(task) = async_ssl_write(gen_var(arg_copy.s)->ssl,
                                           (uint8_t*)gen_var(arg_copy.buf) + gen_var(off),
                                           remain);
            gen_yield_from_task(gen_var(task));
            gen_var(n) = (ssize_t)(intptr_t)future_result(gen_var(task)->future);
        } else {
            gen_var(fut) = async_socket_send(gen_var(arg_copy.s)->sock,
                                             (uint8_t*)gen_var(arg_copy.buf) + gen_var(off),
                                             remain);
            gen_yield(gen_var(fut));
            gen_var(n) = (ssize_t)(intptr_t)future_result(gen_var(fut));
        }


        if (gen_var(n) <= 0) {
            gen_return((void*)(intptr_t)-1);
        }
        gen_var(off) += (size_t)gen_var(n);
    }

    gen_return((void*)0);
    gen_end(NULL);
}

task_t *async_stream_write_all(async_stream_t *s,
                               const void *buf,
                               size_t len)
{
    stream_write_arg_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
    a->s = s;
    a->buf = buf;
    a->len = len;
    return async_stream_write_all_(a);
}

/* ==============================
 * read_until (delimiter)
 * ============================== */

typedef struct {
    async_stream_t *s;
    char            delimiter;
    void           *buf;
    size_t          max_len;
} stream_read_until_arg_t;

task_t* task_arg(async_stream_read_until_) {
    gen_dec_vars(
        stream_read_until_arg_t arg_copy;
        task_t   *task;
        uint8_t   byte;
        size_t    total_read;
    );
    gen_begin(ctx);

    {
        stream_read_until_arg_t *in = (stream_read_until_arg_t*)arg;
        gen_var(arg_copy) = *in;
        free(in);
    }

    gen_var(total_read) = 0;

    while (gen_var(total_read) < gen_var(arg_copy).max_len - 1) {
        gen_var(task) = async_stream_read(gen_var(arg_copy).s, 1, &gen_var(byte));
        gen_yield_from_task(gen_var(task));

        int result = (int)future_result(gen_var(task)->future);
        if (result <= 0) {
            if (gen_var(total_read) == 0) {
                gen_return(-1);
            }
            break;
        }
        ((uint8_t*)gen_var(arg_copy).buf)[gen_var(total_read)++] = gen_var(byte);
        if (gen_var(byte) == gen_var(arg_copy).delimiter) {
            break;
        }
    }

    // 添加 null 终止符
    ((uint8_t*)gen_var(arg_copy).buf)[gen_var(total_read)] = '\0';
    gen_return((void*)(intptr_t)gen_var(total_read));
    gen_end(NULL);
}

task_t* async_stream_read_until(async_stream_t *s,
                                char delimiter,
                                void *buf,
                                size_t max_len)
{
    stream_read_until_arg_t *a = malloc(sizeof(*a));
    if (!a) return NULL;
    a->s = s;
    a->delimiter = delimiter;
    a->buf = buf;
    a->max_len = max_len;
    return async_stream_read_until_(a);
}

/* ============================================================
 * 同步 stream 实现
 * ============================================================ */

typedef enum {
    STREAM_TYPE_SOCKET,
    STREAM_TYPE_SSL
} stream_type_t;

struct sync_stream {
    stream_type_t type;
    union {
        anet_palsock_t sock;
        sync_ssl_t    *ssl;
    } u;
    int closed;
};

/* ==========================================
 * 创建 stream
 * ========================================== */

sync_stream_t* sync_stream_from_socket(anet_palsock_t sock) {
    if (!anet_palsock_is_valid(sock)) {
        return NULL;
    }

    sync_stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->type = STREAM_TYPE_SOCKET;
    s->u.sock = sock;
    s->closed = 0;
    return s;
}

sync_stream_t* sync_stream_from_ssl(sync_ssl_t *ssl) {
    if (!ssl) {
        return NULL;
    }

    sync_stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->type = STREAM_TYPE_SSL;
    s->u.ssl = ssl;
    s->closed = 0;
    return s;
}

void sync_stream_close(sync_stream_t *s) {
    if (!s || s->closed) return;

    if (s->type == STREAM_TYPE_SOCKET) {
        anet_palsock_close(s->u.sock);
    } else if (s->type == STREAM_TYPE_SSL) {
        sync_ssl_close(s->u.ssl);
    }

    s->closed = 1;
}

void sync_stream_destroy(sync_stream_t *s) {
    if (!s) return;

    if (!s->closed) {
        sync_stream_close(s);
    }

    if (s->type == STREAM_TYPE_SSL) {
        sync_ssl_destroy(s->u.ssl);
    }

    free(s);
}

/* ==========================================
 * 同步 IO
 * ========================================== */

static int socket_read(anet_palsock_t sock, void *buf, size_t len) {
    int result = anet_palsock_recv(sock, buf, len, 0);
    return result;
}

static int socket_write(anet_palsock_t sock, const void *buf, size_t len) {
    size_t offset = 0;
    
    while (offset < len) {
        int sent = anet_palsock_send(sock, (const uint8_t*)buf + offset, len - offset, 0);
        if (sent <= 0) return -1;
        offset += sent;
    }
    
    return 0;
}

int sync_stream_read(sync_stream_t *s, size_t max_len, void *buf) {
    if (!s || !buf || max_len == 0 || s->closed) {
        return -1;
    }

    if (s->type == STREAM_TYPE_SOCKET) {
        return socket_read(s->u.sock, buf, max_len);
    } else if (s->type == STREAM_TYPE_SSL) {
        return sync_ssl_read(s->u.ssl, buf, max_len);
    }

    return -1;
}

int sync_stream_read_exactly(sync_stream_t *s, size_t len, void *buf) {
    if (!s || !buf || len == 0 || s->closed) {
        return -1;
    }

    size_t total_read = 0;
    uint8_t *ptr = (uint8_t*)buf;

    while (total_read < len) {
        int bytes_read = sync_stream_read(s, len - total_read, ptr + total_read);
        if (bytes_read <= 0) {
            return -1;
        }
        total_read += bytes_read;
    }

    return 0;
}

int sync_stream_read_until(sync_stream_t *s, char delimiter, void *buf, size_t max_len) {
    if (!s || !buf || max_len == 0 || s->closed) {
        return -1;
    }

    uint8_t *ptr = (uint8_t*)buf;
    size_t total_read = 0;

    while (total_read < max_len - 1) {
        uint8_t c;

        int result = sync_stream_read(s, 1, &c);
        if (result <= 0) {
            if (total_read == 0) return -1;
            break;
        }

        ptr[total_read++] = c;

        if (c == delimiter) {
            break;
        }
    }

    ptr[total_read] = '\0';
    return (int)total_read;
}

int sync_stream_write(sync_stream_t *s, const void *buf, size_t len) {
    if (!s || !buf || len == 0 || s->closed) {
        return -1;
    }

    if (s->type == STREAM_TYPE_SOCKET) {
        return socket_write(s->u.sock, buf, len);
    } else if (s->type == STREAM_TYPE_SSL) {
        return sync_ssl_write(s->u.ssl, buf, len);
    }

    return -1;
}

int sync_stream_write_string(sync_stream_t *s, const char *str) {
    if (!str) return -1;
    return sync_stream_write(s, str, strlen(str));
}

/* ==========================================
 * 工具函数
 * ========================================== */

int sync_stream_is_closed(sync_stream_t *s) {
    return s ? s->closed : 1;
}

anet_palsock_t sync_stream_get_socket(sync_stream_t *s) {
    if (!s || s->type != STREAM_TYPE_SOCKET) {
        return -1;
    }
    return s->u.sock;
}

sync_ssl_t* sync_stream_get_ssl(sync_stream_t *s) {
    if (!s || s->type != STREAM_TYPE_SSL) {
        return NULL;
    }
    return s->u.ssl;
}
