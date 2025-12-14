#pragma once

#include <stddef.h>
#include <stdint.h>
#include "../tls.h"
#include "future_socket.h"
#include "pal_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* ==========================================
     * 异步 stream 接口
     * ========================================== */
    
    typedef struct async_stream async_stream_t;

    // 基于普通 async socket
    async_stream_t* async_stream_from_socket(async_socket_t *sock);

    // 基于异步 SSL
    async_stream_t* async_stream_from_ssl(async_ssl_t *ssl);

    // 关闭 stream
    task_t* async_stream_close(async_stream_t *s);

    // 读至少 1 字节，最多 max_len
    task_t* async_stream_read(async_stream_t *s, size_t max_len, void *buf);

    // 必须读满 len 字节
    task_t* async_stream_read_exactly(async_stream_t *s, size_t len, void *buf);

    // 读到 delimiter（不包含 delimiter）
    // 返回实际读取长度
    task_t* async_stream_read_until(async_stream_t *s, char delimiter, void *buf, size_t max_len);

    // 写至少 1 字节
    task_t* async_stream_write(async_stream_t *s, const void *buf, size_t len);

    // 写完全部
    task_t* async_stream_write_all(async_stream_t *s, const void *buf, size_t len);

    /* ==========================================
     * 同步 stream 接口
     * ========================================== */
    
    typedef struct sync_stream sync_stream_t;

    // 基于普通 socket 创建 stream
    sync_stream_t* sync_stream_from_socket(anet_palsock_t sock);

    // 基于同步 SSL 创建 stream
    sync_stream_t* sync_stream_from_ssl(sync_ssl_t *ssl);

    // 关闭 stream
    void sync_stream_close(sync_stream_t *s);

    // 销毁 stream
    void sync_stream_destroy(sync_stream_t *s);

    // 读取数据（最多 max_len 字节）
    // 返回实际读取的字节数，0表示连接关闭，-1表示错误
    int sync_stream_read(sync_stream_t *s, size_t max_len, void *buf);

    // 必须读满 len 字节
    // 返回0成功，-1失败
    int sync_stream_read_exactly(sync_stream_t *s, size_t len, void *buf);

    // 读到 delimiter（不包含 delimiter）
    // buf 必须有足够空间（max_len）
    // 返回实际读取长度，-1表示错误
    int sync_stream_read_until(sync_stream_t *s, char delimiter, void *buf, size_t max_len);

    // 写入数据
    // 返回0成功，-1失败
    int sync_stream_write(sync_stream_t *s, const void *buf, size_t len);

    // 写入字符串
    // 返回0成功，-1失败
    int sync_stream_write_string(sync_stream_t *s, const char *str);

    // 检查是否已关闭
    int sync_stream_is_closed(sync_stream_t *s);

    // 获取底层 socket（仅用于普通 socket stream）
    anet_palsock_t sync_stream_get_socket(sync_stream_t *s);

    // 获取底层 SSL（仅用于 SSL stream）
    sync_ssl_t* sync_stream_get_ssl(sync_stream_t *s);

#ifdef __cplusplus
}
#endif
