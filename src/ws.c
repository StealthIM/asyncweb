#include "ws.h"
#include "tls.h"
#include "tools.h"
#include "sock/stream.h"
#include "sock/future_socket.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "libcoro.h"

/* ============================================================
 * 内部结构定义
 * ============================================================ */

struct anet_async_ws {
    async_stream_t *stream;
    anet_ws_state_t state;
    char sec_key[64];
    int is_tls;
};

struct anet_sync_ws {
    sync_stream_t *stream;
    anet_ws_state_t state;
    char sec_key[64];
    int is_tls;
};

/* ============================================================
 * 工具函数
 * ============================================================ */

static int base64_encode(const unsigned char* src, int len, char* out, int out_size) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int out_len = 0;
    int i = 0;

    while (i < len) {
        unsigned int octet_a = i < len ? (unsigned char)src[i++] : 0;
        unsigned int octet_b = i < len ? (unsigned char)src[i++] : 0;
        unsigned int octet_c = i < len ? (unsigned char)src[i++] : 0;

        unsigned int triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        if (out_len + 4 >= out_size) return -1;

        out[out_len++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        out[out_len++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        out[out_len++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        out[out_len++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    // 填充
    for (i = 0; i < (3 - len % 3) % 3; i++) {
        out[out_len - 1 - i] = '=';
    }

    out[out_len] = '\0';
    return out_len;
}

static void generate_websocket_key(char out[64]) {
    unsigned char rand_bytes[16];
    for (int i = 0; i < 16; i++) {
        rand_bytes[i] = (unsigned char)(rand() & 0xFF);
    }
    base64_encode(rand_bytes, 16, out, 64);
}

static int parse_url(const char* url, int* is_tls, char* host, int* port, char* path) {
    if (strncmp(url, "ws://", 5) == 0) {
        *is_tls = 0;
        url += 5;
    } else if (strncmp(url, "wss://", 6) == 0) {
        *is_tls = 1;
        url += 6;
    } else {
        return -1;
    }

    const char* slash = strchr(url, '/');
    const char* colon = strchr(url, ':');
    if (!slash) slash = url + strlen(url);

    if (colon && colon < slash) {
        strncpy(host, url, colon - url);
        host[colon - url] = 0;
        *port = atoi(colon + 1);
    } else {
        strncpy(host, url, slash - url);
        host[slash - url] = 0;
        *port = *is_tls ? 443 : 80;
    }

    strcpy(path, *slash ? slash : "/");
    return 0;
}

/* ============================================================
 * 同步WebSocket实现
 * ============================================================ */

anet_status_t anet_sync_ws_connect(const char *url, anet_sync_ws_t **ws_out) {
    char host[256], path[256];
    int port, is_tls;
    
    if (parse_url(url, &is_tls, host, &port, path) != 0) {
        return ANET_ERR;
    }
    
    anet_sync_ws_t *ws = calloc(1, sizeof(*ws));
    ws->state = ANET_WS_CONNECTING;
    ws->is_tls = is_tls;
    
    generate_websocket_key(ws->sec_key);

    // 初始化平台socket
    anet_palsock_init();

    // 创建socket
    anet_palsock_t sock = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 0);
    if (!anet_palsock_is_valid(sock)) {
        anet_palsock_cleanup();
        return ANET_ERR;
    }

    struct sockaddr_storage addr;
    int addr_len;
    if (anet_palsock_resolve(host, &addr, &addr_len) != 0) {
        anet_palsock_close(sock);
        anet_palsock_cleanup();
        return ANET_ERR;
    }

    // 设置端口
    if (addr.ss_family == AF_INET) {
        ((struct sockaddr_in*)&addr)->sin_port = htons(port);
    } else if (addr.ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&addr)->sin6_port = htons(port);
    }

    // 连接
    if (anet_palsock_connect(sock, (struct sockaddr*)&addr, addr_len) != 0) {
        anet_palsock_close(sock);
        anet_palsock_cleanup();
        return ANET_ERR;
    }
    
    if (is_tls) {
        // 创建SSL
        sync_ssl_t *ssl = sync_ssl_create(SYNC_SSL_CLIENT, host);
        if (!ssl) {
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return ANET_ERR;
        }

        sync_ssl_attach_socket(ssl, sock);

        // SSL握手
        if (sync_ssl_handshake(ssl) != 0) {
            sync_ssl_destroy(ssl);
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return ANET_ERR;
        }

        ws->stream = sync_stream_from_ssl(ssl);
        if (!ws->stream) {
            sync_ssl_destroy(ssl);
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return ANET_ERR;
        }
    } else {
        ws->stream = sync_stream_from_socket(sock);
        if (!ws->stream) {
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return ANET_ERR;
        }
    }

    // 发送握手
    char req[1024];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, port, ws->sec_key);

    if (sync_stream_write_string(ws->stream, req) != 0) {
        sync_stream_close(ws->stream);
        anet_palsock_cleanup();
        free(ws);
        return ANET_ERR;
    }
    
    // 验证响应
    char buf[1024];
    if (sync_stream_read_until(ws->stream, '\n', buf, sizeof(buf) - 1) <= 0) {
        sync_stream_close(ws->stream);
        free(ws);
        anet_palsock_cleanup();
        return ANET_ERR;
    }

    if (strstr(buf, "101") == NULL) {
        sync_stream_close(ws->stream);
        free(ws);
        anet_palsock_cleanup();
        return ANET_ERR;
    }

    // 读取剩余头部
    while (1) {
        int len = sync_stream_read_until(ws->stream, '\n', buf, sizeof(buf) - 1);
        if (len <= 0) {
            sync_stream_close(ws->stream);
            free(ws);
            anet_palsock_cleanup();
            return ANET_ERR;
        }

        buf[len] = 0;
        if (strcmp(buf, "\r\n") == 0 || strcmp(buf, "\n") == 0) {
            break;
        }
    }
    
    ws->state = ANET_WS_OPEN;
    anet_palsock_cleanup();
    *ws_out = ws;
    return ANET_OK;
}

anet_status_t anet_sync_ws_send(anet_sync_ws_t *ws, anet_ws_msg_type_t type, const void *data, size_t len) {
    if (!ws || ws->state != ANET_WS_OPEN) {
        return ANET_ERR;
    }
    
    unsigned char header[10];
    int hlen = 0;
    
    header[0] = 0x80 | (type == ANET_WS_TEXT ? 0x1 : 0x2);
    
    if (len <= 125) {
        header[1] = 0x80 | (unsigned char)len;
        hlen = 2;
    } else if (len <= 65535) {
        header[1] = 0x80 | 126;
        header[2] = len >> 8 & 0xFF;
        header[3] = len & 0xFF;
        hlen = 4;
    } else {
        return ANET_ERR;
    }
    
    unsigned char mask[4];
    for (int i = 0; i < 4; i++) mask[i] = rand() & 0xFF;
    memcpy(header + hlen, mask, 4);
    hlen += 4;
    
    char *frame = malloc(hlen + len);
    memcpy(frame, header, hlen);
    for (int i = 0; i < len; i++) {
        frame[hlen + i] = ((char*)data)[i] ^ mask[i % 4];
    }
    
    int result = sync_stream_write(ws->stream, frame, hlen + len);
    free(frame);
    
    return result == 0 ? ANET_OK : ANET_ERR;
}

anet_status_t anet_sync_ws_recv(anet_sync_ws_t *ws, anet_ws_message_t *msg) {
    if (!ws || ws->state != ANET_WS_OPEN) {
        return ANET_ERR;
    }
    
    char hdr[2];
    if (sync_stream_read_exactly(ws->stream, 2, hdr) != 0) {
        return ANET_ERR;
    }
    
    int opcode = hdr[0] & 0x0F;
    int masked = (hdr[1] & 0x80) != 0;
    int len = hdr[1] & 0x7F;
    
    if (opcode == 0x8) {
        ws->state = ANET_WS_CLOSED;
        return ANET_ERR; // 连接关闭
    }
    
    if (opcode == 0x9) {
        // Ping响应
        char pong[2] = { (char)0x8A, 0x00 };
        sync_stream_write(ws->stream, pong, 2);
        return anet_sync_ws_recv(ws, msg); // 递归调用获取真实消息
    }
    
    if (len == 126) {
        char ext[2];
        if (sync_stream_read_exactly(ws->stream, 2, ext) != 0) {
            return ANET_ERR;
        }
        len = ext[0] << 8 | ext[1];
    } else if (len == 127) {
        return ANET_ERR;
    }
    
    char mask[4];
    if (masked) {
        if (sync_stream_read_exactly(ws->stream, 4, mask) != 0) {
            return ANET_ERR;
        }
    }
    
    msg->data = malloc(len + 1);
    if (sync_stream_read_exactly(ws->stream, len, msg->data) != 0) {
        free(msg->data);
        return ANET_ERR;
    }
    
    if (masked) {
        for (int i = 0; i < len; i++) {
            msg->data[i] ^= mask[i % 4];
        }
    }
    
    msg->data[len] = 0;
    msg->len = len;
    msg->type = (opcode == 0x1) ? ANET_WS_TEXT : ANET_WS_BINARY;
    
    return ANET_OK;
}

void anet_sync_ws_close(anet_sync_ws_t *ws) {
    if (!ws) return;
    
    if (ws->state == ANET_WS_OPEN) {
        ws->state = ANET_WS_CLOSING;
        unsigned char closef[2] = {0x88, 0x00};
        sync_stream_write(ws->stream, closef, 2);
    }
    
    sync_stream_close(ws->stream);
    ws->state = ANET_WS_CLOSED;
}

anet_ws_state_t anet_sync_ws_get_state(anet_sync_ws_t *ws) {
    return ws ? ws->state : ANET_WS_CLOSED;
}

void anet_sync_ws_destroy(anet_sync_ws_t *ws) {
    if (ws) {
        if (ws->state == ANET_WS_OPEN) {
            anet_sync_ws_close(ws);
        }
        free(ws);
    }
}

/* ============================================================
 * 异步WebSocket实现
 * ============================================================ */

// 异步WebSocket连接参数扩展
typedef struct {
    const char *url;
    anet_async_ws_t **ws_out;
    
    // 内部状态
    char host[256];
    char path[256];
    int port;
    int is_tls;
    anet_palsock_t sock;
    async_socket_t *async_sock;
    async_ssl_t *async_ssl;
    async_stream_t *stream;
    char sec_key[64];
    char req[1024];
    char buf[1024];
} async_ws_connect_internal_t;

// 异步WebSocket连接协程
task_t* task_arg(anet_async_ws_connect_) {
    gen_dec_vars(
        async_ws_connect_internal_t *conn;
        future_t *fut;
        task_t *task;
        struct sockaddr_storage addr;
        int addr_len;
        int len;
        anet_async_ws_t *ws;
    );
    gen_begin(ctx);

    {
        anet_async_ws_connect_t *in = (anet_async_ws_connect_t*)arg;
        
        // 创建内部连接结构
        gen_var(conn) = calloc(1, sizeof(*gen_var(conn)));
        if (!gen_var(conn)) {
            gen_return((void*)(intptr_t)ANET_ERR);
        }
        
        // 复制参数
        gen_var(conn)->url = in->url;
        gen_var(conn)->ws_out = in->ws_out;
        free(in);
        
        // 解析URL
        if (parse_url(gen_var(conn)->url, &gen_var(conn)->is_tls, gen_var(conn)->host, &gen_var(conn)->port, gen_var(conn)->path) != 0) {
            free(gen_var(conn));
            gen_return((void*)(intptr_t)ANET_ERR);
        }
    }

    // 步骤1: 初始化平台socket
    anet_palsock_init();

    // 步骤2: 创建socket
    gen_var(conn)->sock = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(conn)->sock)) {
        anet_palsock_cleanup();
        free(gen_var(conn));
        gen_return((void*)(intptr_t)ANET_ERR);
    }

    // 步骤3: 解析地址
    if (anet_palsock_resolve(gen_var(conn)->host, &gen_var(addr), &gen_var(addr_len)) != 0) {
        anet_palsock_close(gen_var(conn)->sock);
        anet_palsock_cleanup();
        free(gen_var(conn));
        gen_return((void*)(intptr_t)ANET_ERR);
    }

    // 设置端口
    if (gen_var(addr).ss_family == AF_INET) {
        ((struct sockaddr_in*)&gen_var(addr))->sin_port = htons(gen_var(conn)->port);
    } else if (gen_var(addr).ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&gen_var(addr))->sin6_port = htons(gen_var(conn)->port);
    }

    // 创建异步socket
    gen_var(conn)->async_sock = async_socket_create(gen_var(conn)->sock);
    if (!gen_var(conn)->async_sock) {
        anet_palsock_close(gen_var(conn)->sock);
        anet_palsock_cleanup();
        free(gen_var(conn));
        gen_return((void*)(intptr_t)ANET_ERR);
    }

    // 步骤4: 连接
    gen_var(fut) = async_socket_connect(gen_var(conn)->async_sock, (struct sockaddr*)&gen_var(addr), gen_var(addr_len));
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) {
        anet_palsock_close(gen_var(conn)->sock);
        anet_palsock_cleanup();
        free(gen_var(conn));
        gen_return((void*)(intptr_t)ANET_ERR);
    }

    // 步骤5: 创建SSL（如果是WSS）
    if (gen_var(conn)->is_tls) {
        gen_var(conn)->async_ssl = async_ssl_create(ASYNC_SSL_CLIENT, gen_var(conn)->host);
        if (!gen_var(conn)->async_ssl) {
            anet_palsock_close(gen_var(conn)->sock);
            anet_palsock_cleanup();
            free(gen_var(conn));
            gen_return((void*)(intptr_t)ANET_ERR);
        }

        async_ssl_attach_socket(gen_var(conn)->async_ssl, gen_var(conn)->async_sock);

        // 步骤6: SSL握手
        gen_var(task) = async_ssl_handshake(gen_var(conn)->async_ssl);
        gen_yield_from_task(gen_var(task));

        if (future_result(gen_var(task)->future) != (void*)0) {
            anet_palsock_close(gen_var(conn)->sock);
            anet_palsock_cleanup();
            free(gen_var(conn));
            gen_return((void*)(intptr_t)ANET_ERR);
        }

        gen_var(conn)->stream = async_stream_from_ssl(gen_var(conn)->async_ssl);
        if (!gen_var(conn)->stream) {
            anet_palsock_close(gen_var(conn)->sock);
            anet_palsock_cleanup();
            free(gen_var(conn));
            gen_return((void*)(intptr_t)ANET_ERR);
        }
    } else {
        gen_var(conn)->stream = async_stream_from_socket(gen_var(conn)->async_sock);
        if (!gen_var(conn)->stream) {
            anet_palsock_close(gen_var(conn)->sock);
            anet_palsock_cleanup();
            free(gen_var(conn));
            gen_return((void*)(intptr_t)ANET_ERR);
        }
    }

    // 创建WebSocket对象
    gen_var(ws) = calloc(1, sizeof(*gen_var(ws)));
    if (!gen_var(ws)) {
        if (gen_var(conn)->is_tls) {
            // SSL和async_sock会被async_stream_close清理
        } else {
            async_socket_close(gen_var(conn)->async_sock);
            anet_palsock_close(gen_var(conn)->sock);
        }
        anet_palsock_cleanup();
        free(gen_var(conn));
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    gen_var(ws)->stream = gen_var(conn)->stream;
    gen_var(ws)->state = ANET_WS_CONNECTING;
    gen_var(ws)->is_tls = gen_var(conn)->is_tls;
    generate_websocket_key(gen_var(ws)->sec_key);

    // 步骤7: 发送握手
    snprintf(gen_var(conn)->req, sizeof(gen_var(conn)->req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        gen_var(conn)->path, gen_var(conn)->host, gen_var(conn)->port, gen_var(ws)->sec_key);

    gen_var(task) = async_stream_write_all(gen_var(conn)->stream, gen_var(conn)->req, strlen(gen_var(conn)->req));
    gen_yield_from_task(gen_var(task));

    if (future_result(gen_var(task)->future) != (void*)0) {
        async_stream_close(gen_var(conn)->stream);
        anet_palsock_cleanup();
        free(gen_var(ws));
        free(gen_var(conn));
        gen_return((void*)(intptr_t)ANET_ERR);
    }

    // 步骤8: 验证响应
    gen_var(task) = async_stream_read_until(gen_var(conn)->stream, '\n', gen_var(conn)->buf, sizeof(gen_var(conn)->buf) - 1);
    gen_yield_from_task(gen_var(task));

    gen_var(len) = (int)(intptr_t)future_result(gen_var(task)->future);
    if (gen_var(len) <= 0) {
        async_stream_close(gen_var(conn)->stream);
        free(gen_var(ws));
        free(gen_var(conn));
        gen_return((void*)(intptr_t)ANET_ERR);
    }

    gen_var(conn)->buf[gen_var(len)] = 0;
    if (strstr(gen_var(conn)->buf, "101") == NULL) {
        async_stream_close(gen_var(conn)->stream);
        free(gen_var(ws));
        free(gen_var(conn));
        gen_return((void*)(intptr_t)ANET_ERR);
    }

    // 步骤9: 读取剩余头部
    while (1) {
        gen_var(task) = async_stream_read_until(gen_var(conn)->stream, '\n', gen_var(conn)->buf, sizeof(gen_var(conn)->buf) - 1);
        gen_yield_from_task(gen_var(task));

        gen_var(len) = (int)(intptr_t)future_result(gen_var(task)->future);
        if (gen_var(len) <= 0) {
            async_stream_close(gen_var(conn)->stream);
            free(gen_var(ws));
            free(gen_var(conn));
            gen_return((void*)(intptr_t)ANET_ERR);
        }

        gen_var(conn)->buf[gen_var(len)] = 0;
        if (strcmp(gen_var(conn)->buf, "\r\n") == 0 || strcmp(gen_var(conn)->buf, "\n") == 0) {
            break;
        }
    }
    
    gen_var(ws)->state = ANET_WS_OPEN;
    anet_palsock_cleanup();
    *(gen_var(conn)->ws_out) = gen_var(ws);
    free(gen_var(conn));
    gen_return((void*)(intptr_t)ANET_OK);
    gen_end(NULL);
}

task_t* anet_async_ws_connect(const char *url, anet_async_ws_t **ws) {
    anet_async_ws_connect_t *req = malloc(sizeof(*req));
    if (!req) return NULL;
    
    req->url = url;
    req->ws_out = ws;
    
    task_t *task = anet_async_ws_connect_(req);
    return task;
}

// 异步WebSocket发送参数扩展
typedef struct {
    anet_async_ws_t *ws;
    anet_ws_msg_type_t type;
    const void *data;
    size_t len;
} async_ws_send_internal_t;

// 异步WebSocket发送协程
task_t* task_arg(anet_async_ws_send_) {
    gen_dec_vars(
        async_ws_send_internal_t *send;
        task_t *task;
        unsigned char header[10];
        int hlen;
        unsigned char mask[4];
        char *frame;
    );
    gen_begin(ctx);

    {
        anet_async_ws_send_t *in = (anet_async_ws_send_t*)arg;
        
        // 创建内部发送结构
        gen_var(send) = malloc(sizeof(*gen_var(send)));
        if (!gen_var(send)) {
            gen_return((void*)(intptr_t)ANET_ERR);
        }
        
        // 复制参数
        gen_var(send)->ws = in->ws;
        gen_var(send)->type = in->type;
        gen_var(send)->data = in->data;
        gen_var(send)->len = in->len;
        free(in);
    }

    if (!gen_var(send)->ws || gen_var(send)->ws->state != ANET_WS_OPEN) {
        free(gen_var(send));
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    gen_var(hlen) = 0;
    
    gen_var(header)[0] = 0x80 | (gen_var(send)->type == ANET_WS_TEXT ? 0x1 : 0x2);
    
    if (gen_var(send)->len <= 125) {
        gen_var(header)[1] = 0x80 | (unsigned char)gen_var(send)->len;
        gen_var(hlen) = 2;
    } else if (gen_var(send)->len <= 65535) {
        gen_var(header)[1] = 0x80 | 126;
        gen_var(header)[2] = gen_var(send)->len >> 8 & 0xFF;
        gen_var(header)[3] = gen_var(send)->len & 0xFF;
        gen_var(hlen) = 4;
    } else {
        free(gen_var(send));
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    for (int i = 0; i < 4; i++) gen_var(mask)[i] = rand() & 0xFF;
    memcpy(gen_var(header) + gen_var(hlen), gen_var(mask), 4);
    gen_var(hlen) += 4;
    
    gen_var(frame) = malloc(gen_var(hlen) + gen_var(send)->len);
    memcpy(gen_var(frame), gen_var(header), gen_var(hlen));
    for (int i = 0; i < gen_var(send)->len; i++) {
        gen_var(frame)[gen_var(hlen) + i] = ((char*)gen_var(send)->data)[i] ^ gen_var(mask)[i % 4];
    }
    
    gen_var(task) = async_stream_write_all(gen_var(send)->ws->stream, gen_var(frame), gen_var(hlen) + gen_var(send)->len);
    gen_yield_from_task(gen_var(task));
    
    free(gen_var(frame));
    free(gen_var(send));
    
    if (future_result(gen_var(task)->future) != (void*)0) {
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    gen_return((void*)(intptr_t)ANET_OK);
    gen_end(NULL);
}

task_t* anet_async_ws_send(anet_async_ws_t *ws, anet_ws_msg_type_t type, const void *data, size_t len) {
    anet_async_ws_send_t *req = malloc(sizeof(*req));
    if (!req) return NULL;
    
    req->ws = ws;
    req->type = type;
    req->data = data;
    req->len = len;
    
    task_t *task = anet_async_ws_send_(req);
    return task;
}

// 异步WebSocket接收参数扩展
typedef struct {
    anet_async_ws_t *ws;
    anet_ws_message_t *msg;
    
    // 内部状态
    char hdr[2];
    int opcode;
    int masked;
    int len;
    char mask[4];
} async_ws_recv_internal_t;

// 异步WebSocket接收协程
task_t* task_arg(anet_async_ws_recv_) {
    gen_dec_vars(
        async_ws_recv_internal_t *recv;
        task_t *task;
        char ext[2];
    );
    gen_begin(ctx);

    {
        anet_async_ws_recv_t *in = (anet_async_ws_recv_t*)arg;
        
        // 创建内部接收结构
        gen_var(recv) = malloc(sizeof(*gen_var(recv)));
        if (!gen_var(recv)) {
            gen_return((void*)(intptr_t)ANET_ERR);
        }
        
        // 复制参数
        gen_var(recv)->ws = in->ws;
        gen_var(recv)->msg = in->msg;
        free(in);
    }

    if (!gen_var(recv)->ws || gen_var(recv)->ws->state != ANET_WS_OPEN) {
        free(gen_var(recv));
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    // 步骤1: 读取帧头
    gen_var(task) = async_stream_read_exactly(gen_var(recv)->ws->stream, 2, gen_var(recv)->hdr);
    gen_yield_from_task(gen_var(task));
    
    if (future_result(gen_var(task)->future) != (void*)0) {
        free(gen_var(recv));
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    gen_var(recv)->opcode = gen_var(recv)->hdr[0] & 0x0F;
    gen_var(recv)->masked = (gen_var(recv)->hdr[1] & 0x80) != 0;
    gen_var(recv)->len = gen_var(recv)->hdr[1] & 0x7F;
    
    if (gen_var(recv)->opcode == 0x8) {
        gen_var(recv)->ws->state = ANET_WS_CLOSED;
        free(gen_var(recv));
        gen_return((void*)(intptr_t)ANET_ERR); // 连接关闭
    }
    
    if (gen_var(recv)->opcode == 0x9) {
        // Ping响应
        char pong[2] = { (char)0x8A, 0x00 };
        gen_var(task) = async_stream_write_all(gen_var(recv)->ws->stream, pong, 2);
        gen_yield_from_task(gen_var(task));
        
        if (future_result(gen_var(task)->future) != (void*)0) {
            free(gen_var(recv));
            gen_return((void*)(intptr_t)ANET_ERR);
        }
        
        // 递归调用获取真实消息
        anet_async_ws_recv_t req;
        req.ws = gen_var(recv)->ws;
        req.msg = gen_var(recv)->msg;
        free(gen_var(recv));
        
        gen_var(task) = anet_async_ws_recv_(&req);
        gen_yield_from_task(gen_var(task));
        gen_return(future_result(gen_var(task)->future));
    }
    
    // 步骤2: 读取扩展长度
    if (gen_var(recv)->len == 126) {
        gen_var(task) = async_stream_read_exactly(gen_var(recv)->ws->stream, 2, gen_var(ext));
        gen_yield_from_task(gen_var(task));
        
        if (future_result(gen_var(task)->future) != (void*)0) {
            free(gen_var(recv));
            gen_return((void*)(intptr_t)ANET_ERR);
        }
        gen_var(recv)->len = gen_var(ext)[0] << 8 | gen_var(ext)[1];
    } else if (gen_var(recv)->len == 127) {
        free(gen_var(recv));
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    // 步骤3: 读取掩码
    if (gen_var(recv)->masked) {
        gen_var(task) = async_stream_read_exactly(gen_var(recv)->ws->stream, 4, gen_var(recv)->mask);
        gen_yield_from_task(gen_var(task));
        
        if (future_result(gen_var(task)->future) != (void*)0) {
            free(gen_var(recv));
            gen_return((void*)(intptr_t)ANET_ERR);
        }
    }
    
    // 步骤4: 读取数据
    gen_var(recv)->msg->data = malloc(gen_var(recv)->len + 1);
    gen_var(task) = async_stream_read_exactly(gen_var(recv)->ws->stream, gen_var(recv)->len, gen_var(recv)->msg->data);
    gen_yield_from_task(gen_var(task));
    
    if (future_result(gen_var(task)->future) != (void*)0) {
        free(gen_var(recv)->msg->data);
        free(gen_var(recv));
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    if (gen_var(recv)->masked) {
        for (int i = 0; i < gen_var(recv)->len; i++) {
            gen_var(recv)->msg->data[i] ^= gen_var(recv)->mask[i % 4];
        }
    }
    
    gen_var(recv)->msg->data[gen_var(recv)->len] = 0;
    gen_var(recv)->msg->len = gen_var(recv)->len;
    gen_var(recv)->msg->type = (gen_var(recv)->opcode == 0x1) ? ANET_WS_TEXT : ANET_WS_BINARY;
    
    free(gen_var(recv));
    gen_return((void*)(intptr_t)ANET_OK);
    gen_end(NULL);
}

task_t* anet_async_ws_recv(anet_async_ws_t *ws, anet_ws_message_t *msg) {
    anet_async_ws_recv_t *req = malloc(sizeof(*req));
    if (!req) return NULL;
    
    req->ws = ws;
    req->msg = msg;
    
    task_t *task = anet_async_ws_recv_(req);
    return task;
}

// 异步WebSocket关闭协程
task_t* task_arg(anet_async_ws_close_) {
    gen_dec_vars(
        anet_async_ws_t *ws;
        task_t *task;
        unsigned char closef[2];
    );
    gen_begin(ctx);

    {
        gen_var(ws) = (anet_async_ws_t*)arg;
    }
    
    if (!gen_var(ws)) {
        gen_return((void*)(intptr_t)ANET_ERR);
    }
    
    if (gen_var(ws)->state == ANET_WS_OPEN) {
        gen_var(ws)->state = ANET_WS_CLOSING;
        gen_var(closef)[0] = 0x88;
        gen_var(closef)[1] = 0x00;
        
        gen_var(task) = async_stream_write_all(gen_var(ws)->stream, gen_var(closef), 2);
        gen_yield_from_task(gen_var(task));
        
        // 不管发送是否成功都继续关闭
    }
    
    gen_var(task) = async_stream_close(gen_var(ws)->stream);
    gen_yield_from_task(gen_var(task));
    
    gen_var(ws)->state = ANET_WS_CLOSED;
    gen_return((void*)(intptr_t)ANET_OK);
    gen_end(NULL);
}

task_t* anet_async_ws_close(anet_async_ws_t *ws) {
    if (!ws) return NULL;
    
    task_t *task = anet_async_ws_close_(ws);
    return task;
}

// 获取WebSocket连接状态
anet_ws_state_t anet_async_ws_get_state(anet_async_ws_t *ws) {
    return ws ? ws->state : ANET_WS_CLOSED;
}

// 释放WebSocket消息资源
void anet_ws_message_free(anet_ws_message_t *msg) {
    if (!msg) return;
    
    free(msg->data);
    msg->data = NULL;
    msg->len = 0;
}

// 销毁WebSocket连接
void anet_async_ws_destroy(anet_async_ws_t *ws) {
    if (ws) {
        if (ws->state == ANET_WS_OPEN) {
            // 同步关闭，因为销毁函数不能返回task
            unsigned char closef[2] = {0x88, 0x00};
            async_stream_write_all(ws->stream, closef, 2);
            async_stream_close(ws->stream);
            ws->state = ANET_WS_CLOSED;
        }
        free(ws);
    }
}