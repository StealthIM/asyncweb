#pragma once

#include <stddef.h>
#include <asyncweb/stream.h>
#include <asyncweb/common.h>

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
    int use_tls;                 // 非 0 用 TLS (https),由 scheme 决定而非端口
    const char *path;
    const char **headers;
    const char *body;
    anet_async_http_response_t *response;
} anet_async_http_request_t;

// 发送异步HTTP请求
task_t* anet_async_http_request(anet_async_http_request_t *req);

// 简化的异步GET请求
task_t* anet_async_http_get(const char *url, anet_async_http_response_t *response);

/* ============================================================
 * 流式 (Server-Sent Events) 客户端
 *
 * 用于 text/event-stream 长连接: 服务端持续推 "data:" 行, 每个事件在收到时
 * 立即交付, 不等整条响应结束 (普通 anet_async_http_* 会攒完整 body 才返回,
 * 对常驻不关的 SSE 流会永不返回)。
 *
 * 底层用 libcoro 的 gen_emit: 流式请求 task 边 await socket 读取、边把每个
 * 事件 gen_emit 出去, 驱动器路由给下面的 on_event 回调。消费是回调式 (异步
 * 生成器无法用 gen_for 同步迭代)。事件在回调返回后即失效, 需留存请自行拷贝。
 * ============================================================ */

// 一个 SSE 事件 (一条 "data:" 行去掉前缀后的内容)
typedef struct {
    const char *data;   // 事件数据 (NUL 结尾), 仅回调内有效
    size_t      len;    // data 字节数 (不含结尾 NUL)
} anet_sse_event_t;

// SSE 事件回调。每收到一个 data: 事件调用一次。
typedef void (*anet_sse_cb_t)(const anet_sse_event_t *ev, void *userdata);

// 发起一个流式 (SSE) 请求。参数同 anet_async_http_request_t (method/host/port/
// use_tls/path/headers/body), 但 response 字段忽略 —— 数据经 on_event 交付。
// 返回 task; task future 完成 (ANET_OK/ANET_ERR) 表示流结束 (对端关闭或出错)。
task_t* anet_async_http_stream(anet_async_http_request_t *req,
                               anet_sse_cb_t on_event, void *userdata);

/* ---- 通用二进制流读取 ----
 * 与 SSE 同引擎, 但交付单元是原始字节块 —— 不切行、不认前缀、不解析。库先解析
 * 并跳过 HTTP 响应头 (状态行 + headers 到 \r\n\r\n), 之后的 body 字节逐块 emit,
 * 所以回调拿到的是纯 body 字节流 (适合自定义二进制帧协议 / 文件下载)。
 * 私有帧解析 / 落盘 / 哈希 / Range 由调用方 (如 SDK) 处理 —— asyncweb 不碰 fs。 */

// 一块原始 body 字节 (仅回调内有效, 需留存请自行拷贝)
typedef struct {
    const char *data;
    size_t      len;
} anet_http_chunk_t;

typedef void (*anet_http_chunk_cb_t)(const anet_http_chunk_t *chunk, void *userdata);

// 发起一个 raw 流式请求。参数同上; body 字节 (跳过 HTTP header 后) 经 on_chunk 交付。
task_t* anet_async_http_stream_raw(anet_async_http_request_t *req,
                                   anet_http_chunk_cb_t on_chunk, void *userdata);

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

// 发送 HTTP 请求。use_tls: 非 0 时用 TLS (https),由 scheme 决定而非端口。
anet_status_t anet_sync_http_request(const char *method,
                     const char *host,
                     uint16_t port,
                     int use_tls,
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