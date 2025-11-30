#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ANET_WS_OK = 0,
    ANET_WS_ERR = -1,
    ANET_WS_CLOSED = -2
} anet_ws_status_t;

// WebSocket 句柄（不透明指针）
typedef struct anet_ws_t anet_ws_t;

void anet_ws_init();

/**
 * 创建一个WebSocket连接
 * @param url   WebSocket URL (例如 "ws://echo.websocket.org:80/")
 * @return 连接对象 (NULL = 失败)
 */
anet_ws_t* anet_ws_connect(const char* url);

/**
 * 发送消息
 * @param ws    连接对象
 * @param data  数据
 * @param len   数据长度
 * @param is_text  是否文本帧 (1 = 文本, 0 = 二进制)
 */
anet_ws_status_t anet_ws_send(anet_ws_t* ws, const void* data, int len, int is_text);

/**
 * 接收消息（阻塞）
 * @param ws    连接对象
 * @param buffer 缓存区
 * @param maxlen 缓存大小
 * @param is_text 输出参数：是否文本帧
 * @return 接收的字节数，负数 = 错误
 */
int anet_ws_recv(anet_ws_t* ws, void* buffer, int maxlen, int* is_text);

/**
 * 关闭连接
 */
void anet_ws_close(anet_ws_t* ws);

#ifdef __cplusplus
}
#endif
