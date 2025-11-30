#include "sync/network.h"
#include "tls.h"

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <ctype.h>

#include "tools.h"

#pragma comment(lib, "ws2_32.lib")

anet_status_t anet_init() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa) == 0 ? ANET_OK : ANET_ERR;
}

void anet_cleanup() {
    WSACleanup();
}


// 解析 Content-Length
static int parse_content_length(const char* headers) {
    const char* p = strcasestr(headers, "Content-Length:");
    if (p) {
        char* endptr;
        long val = strtol(p + 15, &endptr, 10);
        return endptr != p + 15 ? (int)val : -1;
    }
    return -1;
}

// 检查 chunked
static int is_chunked(const char* headers) {
    return strcasestr(headers, "Transfer-Encoding: chunked") != NULL;
}

// send/recv 回调统一接口
typedef int (*send_func_t)(void* ctx, const char* buf, int len);
typedef int (*recv_func_t)(void* ctx, char* buf, int maxlen);

// socket 分别实现
static int send_all_socket(void* ctx, const char* buf, int len) {
    SOCKET sock = *(SOCKET*)ctx;
    int sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int recv_all_socket(void* ctx, char* buf, int maxlen) {
    SOCKET sock = *(SOCKET*)ctx;
    return recv(sock, buf, maxlen, 0);
}

// TLS 分别实现
static int send_all_tls(void* ctx, const char* buf, int len) {
    anet_tls_ctx_t* tls = ctx;
    int sent = 0;
    while (sent < len) {
        int n = anet_tls_send(tls, buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int recv_all_tls(void* ctx, char* buf, int maxlen) {
    anet_tls_ctx_t* tls = ctx;
    return anet_tls_recv(tls, buf, maxlen);
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
    *header_len = (int)(header_end - response + 4);
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

static int establish_connection_tls(const char *host, int port, SOCKET *out_sock, anet_tls_ctx_t **out_tls) {
    anet_tls_ctx_t* tls_ctx = anet_tls_create();
    if (!tls_ctx) return -1;
    if (anet_tls_connect(tls_ctx, host, port) != 0) {
        anet_tls_destroy(tls_ctx);
        return -1;
    }
    *out_tls = tls_ctx;
    *out_sock = INVALID_SOCKET;
    return 0;
}

static int establish_connection_nontls(const char *host, int port, SOCKET *out_sock, anet_tls_ctx_t **out_tls) {
    struct hostent* he = gethostbyname(host);
    if (!he) return -1;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return -1;
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    memcpy(&server.sin_addr, he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        closesocket(sock);
        return -1;
    }
    *out_sock = sock;
    *out_tls = NULL;
    return 0;
}

// 建立连接（socket 或 TLS）
static int establish_connection(const char* host, int port, int use_tls, SOCKET* out_sock, anet_tls_ctx_t** out_tls) {
    if (use_tls) {
        return establish_connection_tls(host, port, out_sock, out_tls);
    }
    return establish_connection_nontls(host, port, out_sock, out_tls);
}

// 发送数据（请求头和body）
static int send_http_data(send_func_t send_func, void* ctx, const char* request, int req_len, const char* body) {
    if (send_func(ctx, request, req_len) < 0) return -1;
    if (body && send_func(ctx, body, strlen(body)) < 0) return -1;
    return 0;
}

// 资源清理
static void cleanup_connection(int use_tls, SOCKET sock, anet_tls_ctx_t* tls_ctx) {
    if (use_tls && tls_ctx) {
        anet_tls_close(tls_ctx);
        anet_tls_destroy(tls_ctx);
    }
    if (!use_tls && sock != INVALID_SOCKET) {
        closesocket(sock);
    }
}

// 接收响应体
static int receive_http_body(char* response, int maxlen, int header_len, int content_length, int chunked, recv_func_t recv_func, void* ctx) {
    char* body_ptr = response + header_len;
    int body_bytes = strlen(body_ptr);
    int total;
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
        total = decoded >= 0 ? header_len + decoded : header_len + received;
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
    int use_tls = port == 443;
    SOCKET sock = INVALID_SOCKET;
    anet_tls_ctx_t* tls_ctx = NULL;
    send_func_t send_func = NULL;
    recv_func_t recv_func = NULL;
    void* ctx = NULL;
    int total = 0;
    int ret = ANET_ERR;

    // 构造请求
    char request[2048];
    int req_len = build_http_request(method, host, path, headers, body, request, sizeof(request));
    if (req_len <= 0) return ANET_ERR;

    // 建立连接
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

    // 发送请求
    if (send_http_data(send_func, ctx, request, req_len, body) < 0) goto cleanup;

    // 接收响应头
    int header_len = 0;
    total = receive_response(response, maxlen, &header_len, recv_func, ctx);
    if (total < 0) goto cleanup;

    // 解析响应体
    int content_length = parse_content_length(response);
    int chunked = is_chunked(response);
    total = receive_http_body(response, maxlen, header_len, content_length, chunked, recv_func, ctx);
    if (total < 0) goto cleanup;

    ret = ANET_OK;

cleanup:
    cleanup_connection(use_tls, sock, tls_ctx);
    return ret;
}
