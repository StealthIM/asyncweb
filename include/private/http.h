#pragma once

#include <stddef.h>
#include "sock/stream.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * 异步HTTP接口
 * ============================================================ */

// HTTP 响应结构
typedef struct {
    int status_code;
    char *status_text;
    char *headers;
    size_t headers_len;
    char *body;
    size_t body_len;
} anet_async_http_response_t;

// 异步HTTP请求参数
typedef struct {
    const char *method;
    const char *host;
    uint16_t port;
    const char *path;
    const char **headers;
    const char *body;
    anet_async_http_response_t *response;
} anet_async_http_request_t;

// 发送异步HTTP请求
task_t* anet_async_http_request(anet_async_http_request_t *req);

// 简化的异步GET请求
task_t* anet_async_http_get(const char *url, anet_async_http_response_t *response);

// 简化的异步POST请求
task_t* anet_async_http_post(const char *url, const char *content_type, const char *body, anet_async_http_response_t *response);

// 释放HTTP响应资源
void anet_http_response_free(anet_async_http_response_t *response);

/* ============================================================
 * 同步HTTP接口
 * ============================================================ */

// HTTP 响应结构
typedef struct {
    int status_code;
    char *status_text;
    char *headers;
    size_t headers_len;
    char *body;
    size_t body_len;
} anet_sync_http_response_t;

// 发送 HTTP 请求
anet_status_t anet_sync_http_request(const char *method,
                     const char *host,
                     uint16_t port,
                     const char *path,
                     const char **headers,
                     const char *body,
                     anet_sync_http_response_t *response);

// 释放 HTTP 响应资源
void anet_sync_http_response_free(anet_sync_http_response_t *response);

// 简化的 GET 请求
anet_status_t anet_sync_http_get(const char *url, anet_sync_http_response_t *response);

// 简化的 POST 请求
anet_status_t anet_sync_http_post(const char *url, const char *content_type, const char *body, anet_sync_http_response_t *response);

#ifdef __cplusplus
}
#endif