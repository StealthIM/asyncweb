#pragma once

#include <stddef.h>
#include "sock/stream.h"
#include "common.h"

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