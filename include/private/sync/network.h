#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ANET_OK = 1,
    ANET_ERR = 0,
} anet_status_t;

anet_status_t anet_init();

/**
 * 通用 HTTP 请求
 * @param method   HTTP 方法 (GET/POST/PUT/DELETE...)
 * @param host     目标主机 (例如 "example.com")
 * @param port     目标端口 (通常 80)
 * @param path     请求路径 (例如 "/api/test")
 * @param headers  HTTP 头数组, 最后一个元素必须为 NULL
 * @param body     请求体，可以为 NULL
 * @param response 响应缓存区
 * @param maxlen   响应缓存区大小
 */
anet_status_t anet_http_request(
    const char* method,
    const char* host,
    int port,
    const char* path,
    const char** headers,
    const char* body,
    char* response,
    int maxlen
);

int decode_chunked(const char* src, int src_len, char* dst, int dst_maxlen);

void anet_cleanup();

#ifdef __cplusplus
}
#endif
