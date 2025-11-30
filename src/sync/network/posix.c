#include "sync/network.h"
#include "tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/types.h>

#include "tools.h"

anet_status_t anet_init() {
    // POSIX 不需要初始化 socket
    return ANET_OK;
}

void anet_cleanup() {
    // POSIX 不需要清理
}

// send/recv 回调统一接口
typedef int (*send_func_t)(void* ctx, const char* buf, int len);
typedef int (*recv_func_t)(void* ctx, char* buf, int maxlen);

// socket 分别实现
static int send_all_socket(void* ctx, const char* buf, int len) {
    int sock = *(int*)ctx;
    int sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int recv_all_socket(void* ctx, char* buf, int maxlen) {
    int sock = *(int*)ctx;
    return recv(sock, buf, maxlen, 0);
}

// TLS 分别实现
static int send_all_tls(void* ctx, const char* buf, int len) {
    anet_tls_ctx_t* tls = (anet_tls_ctx_t*)ctx;
    int sent = 0;
    while (sent < len) {
        int n = anet_tls_send(tls, buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int recv_all_tls(void* ctx, char* buf, int maxlen) {
    anet_tls_ctx_t* tls = (anet_tls_ctx_t*)ctx;
    return anet_tls_recv(tls, buf, maxlen);
}

// 解析 Content-Length
static int parse_content_length(const char* headers) {
    const char* p = strcasestr(headers, "Content-Length:");
    if (p) {
        char* endptr;
        long val = strtol(p + 15, &endptr, 10);
        return (endptr != p + 15) ? (int)val : -1;
    }
    return -1;
}

// 检查 chunked
static int is_chunked(const char* headers) {
    return (strcasestr(headers, "Transfer-Encoding: chunked") != NULL);
}

// 接收 HTTP 响应头
static int receive_response(char* response, int maxlen, int* header_len,
                            recv_func_t recv_func, void* ctx) {
    int total = 0;
    int header_done = 0;
    char* header_end = NULL;

    while (!header_done) {
        int recv_size = recv_func(ctx, response + total, maxlen - total - 1);
        if (recv_size <= 0) break;
        total += recv_size;
        response[total] = '\0';
        header_end = strstr(response, "\r\n\r\n");
        if (header_end) header_done = 1;
    }

    if (!header_end) return -1;
    *header_len = (int)((header_end - response) + 4);
    return total;
}

// 构造 HTTP 请求报文
static int build_http_request(const char* method, const char* host, const char* path, const char** headers, const char* body, char* out, int outlen) {
    int n = snprintf(out, outlen, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host);
    if (headers) {
        for (int i = 0; headers[i]; i++)
            n += snprintf(out + n, outlen - n, "%s\r\n", headers[i]);
    }
    if (body) n += snprintf(out + n, outlen - n, "Content-Length: %zu\r\n", strlen(body));
    n += snprintf(out + n, outlen - n, "Connection: close\r\n\r\n");
    return n;
}

// 建立连接（socket 或 TLS）
static int establish_connection(const char* host, int port, int use_tls, int* out_sock, anet_tls_ctx_t** out_tls) {
    if (use_tls) {
        anet_tls_ctx_t* tls_ctx = anet_tls_create();
        if (!tls_ctx) return -1;
        if (anet_tls_connect(tls_ctx, host, port) != 0) {
            anet_tls_destroy(tls_ctx);
            return -1;
        }
        *out_tls = tls_ctx;
        *out_sock = -1;
        return 0;
    } else {
        struct addrinfo hints, *res;
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%d", port);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

        int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) {
            freeaddrinfo(res);
            return -1;
        }

        if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
            close(sock);
            freeaddrinfo(res);
            return -1;
        }

        freeaddrinfo(res);
        *out_sock = sock;
        *out_tls = NULL;
        return 0;
    }
}

// 发送数据
static int send_http_data(send_func_t send_func, void* ctx, const char* request, int req_len, const char* body) {
    if (send_func(ctx, request, req_len) < 0) return -1;
    if (body && send_func(ctx, body, strlen(body)) < 0) return -1;
    return 0;
}

// 资源清理
static void cleanup_connection(int use_tls, int sock, anet_tls_ctx_t* tls_ctx) {
    if (use_tls && tls_ctx) {
        anet_tls_close(tls_ctx);
        anet_tls_destroy(tls_ctx);
    }
    if (!use_tls && sock >= 0) {
        close(sock);
    }
}

// 接收响应体
static int receive_http_body(char* response, int maxlen, int header_len, int content_length, int chunked, recv_func_t recv_func, void* ctx) {
    char* body_ptr = response + header_len;
    int body_bytes = strlen(body_ptr);
    int total = header_len + body_bytes;

    if (content_length > 0) {
        while (body_bytes < content_length) {
            int recv_size = recv_func(ctx, body_ptr + body_bytes, maxlen - header_len - body_bytes - 1);
            if (recv_size <= 0) break;
            body_bytes += recv_size;
        }
        body_ptr[body_bytes] = '\0';
        total = header_len + body_bytes;
    } else if (chunked) {
        int received = body_bytes;
        while (1) {
            int recv_size = recv_func(ctx, body_ptr + received, maxlen - header_len - received - 1);
            if (recv_size <= 0) break;
            received += recv_size;
        }
        int decoded = decode_chunked(body_ptr, received, body_ptr, maxlen - header_len);
        total = (decoded >= 0) ? header_len + decoded : header_len + received;
    } else {
        while (1) {
            int recv_size = recv_func(ctx, body_ptr + body_bytes, maxlen - header_len - body_bytes - 1);
            if (recv_size <= 0) break;
            body_bytes += recv_size;
        }
        body_ptr[body_bytes] = '\0';
        total = header_len + body_bytes;
    }
    return total;
}

// 主函数重构
anet_status_t anet_http_request(
    const char* method,
    const char* host,
    int port,
    const char* path,
    const char** headers,
    const char* body,
    char* response,
    int maxlen
) {
    int use_tls = (port == 443);
    int sock = -1;
    anet_tls_ctx_t* tls_ctx = NULL;
    send_func_t send_func = NULL;
    recv_func_t recv_func = NULL;
    void* ctx = NULL;
    int total = 0;
    int ret = ANET_ERR;

    char request[2048];
    int req_len = build_http_request(method, host, path, headers, body, request, sizeof(request));
    if (req_len <= 0) return ANET_ERR;

    if (establish_connection(host, port, use_tls, &sock, &tls_ctx) != 0) return ANET_ERR;

    if (use_tls) {
        send_func = send_all_tls;
        recv_func = recv_all_tls;
        ctx = tls_ctx;
    } else {
        send_func = send_all_socket;
        recv_func = recv_all_socket;
        ctx = &sock;
    }

    if (send_http_data(send_func, ctx, request, req_len, body) < 0) goto cleanup;

    int header_len = 0;
    total = receive_response(response, maxlen, &header_len, recv_func, ctx);
    if (total < 0) goto cleanup;

    int content_length = parse_content_length(response);
    int chunked = is_chunked(response);

    total = receive_http_body(response, maxlen, header_len, content_length, chunked, recv_func, ctx);
    if (total < 0) goto cleanup;

    ret = ANET_OK;

cleanup:
    cleanup_connection(use_tls, sock, tls_ctx);
    return ret;
}
