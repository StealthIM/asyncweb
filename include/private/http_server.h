#pragma once

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "libcoro.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * 高层异步 HTTP/1.1 服务端
 *
 * 基于已验证的 async_listener/accept 原语,封装:
 *   - accept 循环 (每个服务器一个协程)
 *   - 每连接一个协程:读请求行+头部+body、调 handler、写响应、关闭
 *
 * 支持明文 HTTP 与 HTTPS (见 anet_http_server_use_tls)。
 * 当前限制:单次请求/响应后关闭连接 (Connection: close 语义);
 * 请求缓冲固定上限。
 * ============================================================ */

// 服务端收到的请求 (指针在 handler 调用期间有效)
typedef struct {
    const char *method;    // "GET" / "POST" ...
    const char *path;      // "/foo"
    const char *body;      // 请求体 (可能为 NULL)
    size_t      body_len;
} anet_http_server_request_t;

// handler 填写的响应
typedef struct {
    int         status_code;    // 默认 200
    const char *status_text;    // 默认 "OK"
    const char *content_type;   // 默认 "text/plain"
    const char *body;           // 响应体 (可为 NULL)
    size_t      body_len;       // 0 时对非 NULL body 取 strlen
} anet_http_server_response_t;

// 请求处理回调。resp 已预置默认值,handler 覆盖需要的字段即可。
typedef void (*anet_http_handler_t)(const anet_http_server_request_t *req,
                                    anet_http_server_response_t *resp,
                                    void *userdata);

typedef struct anet_http_server anet_http_server_t;

// 创建并绑定监听 127.0.0.1:port (port==0 时用临时端口)。失败返回 NULL。
anet_http_server_t* anet_http_server_create(uint16_t port,
                                            anet_http_handler_t handler,
                                            void *userdata);

// 启用 HTTPS:每个连接在读请求前先做服务端 TLS 握手。cert_path/key_path
// 为 PEM 文件路径。须在 anet_http_server_run 之前调用。成功返回 0,失败 -1。
int anet_http_server_use_tls(anet_http_server_t *server,
                             const char *cert_path,
                             const char *key_path);

// 实际绑定的端口 (port==0 时用来取临时端口)。
uint16_t anet_http_server_port(anet_http_server_t *server);

// 返回 accept 循环协程 task。交给 loop_run 或 task_run 驱动。
task_t* anet_http_server_run(anet_http_server_t *server);

// 停止接受新连接 (唤醒并退出 accept 循环)。
void anet_http_server_stop(anet_http_server_t *server);

// 释放服务器资源 (调用前应已 stop)。
void anet_http_server_destroy(anet_http_server_t *server);

#ifdef __cplusplus
}
#endif
