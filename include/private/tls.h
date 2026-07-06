#pragma once

#include <stddef.h>
#include "libcoro.h"
#include "sock/future_socket.h"
#include "sock/pal_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

    // =======================================================
    // 异步 SSL 接口
    // =======================================================
    
    typedef struct async_ssl async_ssl_t;

    typedef enum {
        ASYNC_SSL_CLIENT,
        ASYNC_SSL_SERVER
    } async_ssl_role_t;

    // 创建 SSL 会话（不握手）
    async_ssl_t* async_ssl_create(async_ssl_role_t role,
                                  const char *hostname /* SNI, 可为空 */);

    // 创建服务端 SSL 会话:加载证书链与私钥,设为 accept 模式(不校验客户端)。
    // cert_path/key_path 为 PEM 文件路径。失败返回 NULL。
    async_ssl_t* async_ssl_create_server(const char *cert_path,
                                         const char *key_path);

    // ---- 内存证书版 (嵌入式 / NO_FILESYSTEM: 无文件系统时用) ----
    // 证书/密钥以内存 buffer (DER 或 PEM) 传入, is_der 非 0 表示 DER (ASN.1)。

    // 客户端:用内存 CA 证书校验对端。ca 可为 NULL (则不校验, 仅测试用)。
    // hostname 为 SNI + 校验名, 可为空。失败返回 NULL。
    async_ssl_t* async_ssl_create_mem(async_ssl_role_t role,
                                      const char *hostname,
                                      const unsigned char *ca, int ca_len,
                                      int is_der);

    // 服务端:用内存证书链 + 私钥。设为 accept 模式 (不校验客户端)。失败返回 NULL。
    async_ssl_t* async_ssl_create_server_mem(const unsigned char *cert, int cert_len,
                                             const unsigned char *key, int key_len,
                                             int is_der);

    void async_ssl_destroy(async_ssl_t *ssl);

    // 绑定 socket（必须是 async_socket）
    void async_ssl_attach_socket(async_ssl_t *ssl,
                                 async_socket_t *sock);

    // TLS 握手
    task_t* async_ssl_handshake(async_ssl_t *ssl);

    // 读明文（自动处理 WANT_READ / WANT_WRITE）
    task_t* async_ssl_read(async_ssl_t *ssl,
                              void *buf,
                              size_t len);

    // 写明文
    task_t* async_ssl_write(async_ssl_t *ssl,
                               const void *buf,
                               size_t len);

    // 关闭（发送 close_notify）
    task_t* async_ssl_close(async_ssl_t *ssl);

    // 是否已关闭
    int async_ssl_is_closed(async_ssl_t *ssl);

    // =======================================================
    // 后端无关的 crypto 原语 (供 WS 握手用,由各 TLS 后端实现)
    //
    // WebSocket 握手需要随机数 (Sec-WebSocket-Key) 和 SHA1
    // (Sec-WebSocket-Accept),但这不该绑死在某个 TLS 库上。
    // 每个后端 (openssl.c / wolfssl.c) 各用自己的 crypto 实现。
    // =======================================================

    // 生成 len 字节的密码学随机数写入 buf。成功返回 0,失败 -1。
    int anet_tls_rand_bytes(unsigned char *buf, size_t len);

    // 计算 data[0..len) 的 SHA1,写入 out (须 >= 20 字节)。成功返回 0,失败 -1。
    int anet_tls_sha1(const unsigned char *data, size_t len, unsigned char *out);

    // =======================================================
    // 同步 SSL 接口
    // =======================================================
    
    typedef struct sync_ssl sync_ssl_t;

    typedef enum {
        SYNC_SSL_CLIENT,
        SYNC_SSL_SERVER
    } sync_ssl_role_t;

    // 创建SSL会话
    sync_ssl_t* sync_ssl_create(sync_ssl_role_t role, const char *hostname);

    // 绑定socket
    void sync_ssl_attach_socket(sync_ssl_t *ssl, anet_palsock_t sock);

    // SSL握手（阻塞直到完成）
    // 返回0成功，-1失败
    int sync_ssl_handshake(sync_ssl_t *ssl);

    // 同步读取（阻塞直到读取完成或出错）
    // 返回读取的字节数，-1表示错误
    int sync_ssl_read(sync_ssl_t *ssl, void *buf, size_t len);

    // 同步写入（阻塞直到写入完成或出错）
    // 返回0成功，-1失败
    int sync_ssl_write(sync_ssl_t *ssl, const void *buf, size_t len);

    // 关闭SSL连接
    void sync_ssl_close(sync_ssl_t *ssl);

    // 销毁SSL对象
    void sync_ssl_destroy(sync_ssl_t *ssl);

    // 检查是否已关闭
    int sync_ssl_is_closed(sync_ssl_t *ssl);

#ifdef __cplusplus
}
#endif
