#pragma once

#include <stddef.h>
#include <asyncweb/stream.h>
#include <asyncweb/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * 异步WebSocket接口
 * ============================================================ */

// WebSocket 消息类型
typedef enum {
    ANET_WS_TEXT = 0,
    ANET_WS_BINARY = 1,
} anet_ws_msg_type_t;

// WebSocket 连接状态
typedef enum {
    ANET_WS_CONNECTING = 0,
    ANET_WS_OPEN = 1,
    ANET_WS_CLOSING = 2,
    ANET_WS_CLOSED = 3,
} anet_ws_state_t;

// WebSocket 连接对象
typedef struct anet_async_ws anet_async_ws_t;

// WebSocket 消息结构
typedef struct {
    anet_ws_msg_type_t type;
    char *data;
    size_t len;
} anet_ws_message_t;

// 异步WebSocket连接参数结构
typedef struct {
    const char *url;
    anet_async_ws_t **ws_out;
    // wss 内存 CA (嵌入式 / NO_FILESYSTEM): 非 NULL 时用内存 CA 校验对端。
    const unsigned char *ca_mem;
    int                  ca_mem_len;
    int                  ca_is_der;
    // 额外握手请求头 (如 "Authorization: Bearer xxx"): NULL 结尾的字符串数组,
    // 每项不含结尾 CRLF (库自动加)。NULL 表示无额外头。生命周期须覆盖握手期。
    const char        **extra_headers;
} anet_async_ws_connect_t;

// 异步WebSocket发送参数结构
typedef struct {
    anet_async_ws_t *ws;
    anet_ws_msg_type_t type;
    const void *data;
    size_t len;
} anet_async_ws_send_t;

// 异步WebSocket接收参数结构
typedef struct {
    anet_async_ws_t *ws;
    anet_ws_message_t *msg;
} anet_async_ws_recv_t;

// 异步连接到WebSocket服务器
task_t* anet_async_ws_connect(const char *url, anet_async_ws_t **ws);

// 同 anet_async_ws_connect,但 wss 时用内存 CA 校验对端 (嵌入式 / NO_FILESYSTEM)。
// ca 为 DER 或 PEM buffer (is_der 非 0 表示 DER), 不拷贝, 生命周期须覆盖握手期。
// ca 可为 NULL (则不校验对端, 仅测试用)。
task_t* anet_async_ws_connect_mem(const char *url,
                                  const unsigned char *ca, int ca_len, int is_der,
                                  anet_async_ws_t **ws);

// 完整参数版: 支持额外握手请求头 (如 Authorization)。req 由调用方栈上或堆上
// 提供, 库内部拷贝所需字段; 但 extra_headers 指向的字符串数组不拷贝, 生命周期
// 须覆盖握手期。返回 task。
task_t* anet_async_ws_connect_ex(const anet_async_ws_connect_t *req);

// 异步发送WebSocket消息
task_t* anet_async_ws_send(anet_async_ws_t *ws, anet_ws_msg_type_t type, const void *data, size_t len);

// 异步接收WebSocket消息
task_t* anet_async_ws_recv(anet_async_ws_t *ws, anet_ws_message_t *msg);

// 异步关闭WebSocket连接
task_t* anet_async_ws_close(anet_async_ws_t *ws);

// 获取WebSocket连接状态
anet_ws_state_t anet_async_ws_get_state(anet_async_ws_t *ws);

// 释放WebSocket消息资源
void anet_ws_message_free(anet_ws_message_t *msg);

// 销毁WebSocket连接
void anet_async_ws_destroy(anet_async_ws_t *ws);

/* ============================================================
 * WebSocket 服务端升级
 * ============================================================ */

// 服务端握手结果 (由 anet_async_ws_accept task 返回的 future result 携带)
typedef struct {
    anet_socket_t   *sock;      // 传入的已 accept socket
    anet_async_ws_t **ws_out;    // 成功时写入服务端 WS 连接
    int               tls;       // 非 0:先做服务端 TLS 握手 (wss)
    const char       *cert_path; // tls 时的 PEM 证书链路径
    const char       *key_path;  // tls 时的 PEM 私钥路径
    // 内存证书 (嵌入式 / NO_FILESYSTEM): 非 NULL 时优先于 cert_path/key_path。
    const unsigned char *cert_mem;
    int                  cert_mem_len;
    const unsigned char *key_mem;
    int                  key_mem_len;
    int                  cert_is_der;
} anet_async_ws_accept_t;

// 在一条已 accept 的 async socket 上完成服务端 WS 握手:
// 读取 Upgrade 请求头、校验 Sec-WebSocket-Key、回 101 响应,
// 成功后 *ws_out 得到 is_server 模式的连接 (send 不加掩码)。
// future result: ANET_OK / ANET_ERR。
// 所有权:task 接管 sock —— 成功时转交给 *ws_out (经其 stream),
// 失败时由 task 自行关闭释放。调用方在调用后不应再 close/free sock。
task_t* anet_async_ws_accept(anet_socket_t *sock, anet_async_ws_t **ws_out);

// 同 anet_async_ws_accept,但先在 sock 上完成服务端 TLS 握手 (wss)。
// cert_path/key_path 为 PEM 文件路径,须在握手前有效。
task_t* anet_async_ws_accept_tls(anet_socket_t *sock,
                                 const char *cert_path,
                                 const char *key_path,
                                 anet_async_ws_t **ws_out);

// 同 anet_async_ws_accept_tls,但用内存证书 (嵌入式 / NO_FILESYSTEM)。
// cert/key 为 DER 或 PEM buffer (is_der 非 0 表示 DER), 不拷贝, 生命周期须
// 覆盖握手期。
task_t* anet_async_ws_accept_tls_mem(anet_socket_t *sock,
                                     const unsigned char *cert, int cert_len,
                                     const unsigned char *key, int key_len,
                                     int is_der,
                                     anet_async_ws_t **ws_out);

/* ============================================================
 * 同步WebSocket接口
 * ============================================================ */

// WebSocket 连接对象
typedef struct anet_sync_ws anet_sync_ws_t;

// 同步连接到WebSocket服务器
anet_status_t anet_sync_ws_connect(const char *url, anet_sync_ws_t **ws);

// 同步发送WebSocket消息
anet_status_t anet_sync_ws_send(anet_sync_ws_t *ws, anet_ws_msg_type_t type, const void *data, size_t len);

// 同步接收WebSocket消息
anet_status_t anet_sync_ws_recv(anet_sync_ws_t *ws, anet_ws_message_t *msg);

// 同步关闭WebSocket连接
void anet_sync_ws_close(anet_sync_ws_t *ws);

// 获取WebSocket连接状态
anet_ws_state_t anet_sync_ws_get_state(anet_sync_ws_t *ws);

// 销毁WebSocket连接
void anet_sync_ws_destroy(anet_sync_ws_t *ws);

#ifdef __cplusplus
}
#endif