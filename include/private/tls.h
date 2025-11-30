#pragma once

#include <libcoro.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct anet_tls_ctx anet_tls_ctx_t;

// 初始化 TLS 库（一次即可）
int anet_tls_init(void);

// 清理 TLS 库
int anet_tls_cleanup(void);

// 创建 TLS 上下文
anet_tls_ctx_t* anet_tls_create(void);

// 销毁上下文
void anet_tls_destroy(anet_tls_ctx_t* ctx);

// 连接到 host:port
int anet_tls_connect(anet_tls_ctx_t* ctx, const char* host, int port);

task_t *anet_tls_connect_async(loop_t *loop, anet_tls_ctx_t* ctx, const char* host, int port);

// 发送数据
int anet_tls_send(anet_tls_ctx_t* ctx, const char* buf, int len);

future_t *anet_tls_send_async(loop_t *loop, anet_tls_ctx_t* ctx, const char* buf, int len);

// 接收数据
int anet_tls_recv(anet_tls_ctx_t* ctx, char* buf, int maxlen);

future_t *anet_tls_recv_async(loop_t *loop, anet_tls_ctx_t* ctx, char* buf, int maxlen);

// 关闭连接
void anet_tls_close(anet_tls_ctx_t* ctx);

#ifdef __cplusplus
}
#endif
