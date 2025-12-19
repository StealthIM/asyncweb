#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asyncweb.h"

int test_sync_ws() {
    // 初始化网络库
    if (anet_init() != ANET_OK) {
        printf("Network initialization failed\n");
        return 1;
    }
    
    anet_sync_ws_t *ws;
    anet_ws_message_t msg;
    unsigned char binary_data[] = {0x01, 0x02, 0x03, 0x04, 0x05};

    printf("\nTesting sync WebSocket connection to wss://echo.websocket.org\n");

    // 测试安全WebSocket连接
    if (anet_sync_ws_connect("wss://echo.websocket.org", &ws) != ANET_OK) {
        printf("Secure WebSocket connect failed\n");
        anet_cleanup();
        return 1;
    }

    printf("Connected to secure WebSocket server!\n");

    if (anet_sync_ws_recv(ws, &msg) != ANET_OK) {
        printf("Error receiving secure message\n");
        anet_sync_ws_destroy(ws);
        anet_cleanup();
        return 1;
    }
    printf("Received first secure message: %s\n", msg.data);
    anet_ws_message_free(&msg);


    // 发送测试消息
    const char *secure_msg = "Hello, Secure WebSocket!";
    if (anet_sync_ws_send(ws, ANET_WS_TEXT, secure_msg, strlen(secure_msg)) != ANET_OK) {
        printf("Error sending secure message\n");
        anet_sync_ws_destroy(ws);
        anet_cleanup();
        return 1;
    }

    // 接收回显
    if (anet_sync_ws_recv(ws, &msg) != ANET_OK) {
        printf("Error receiving secure message\n");
        anet_sync_ws_destroy(ws);
        anet_cleanup();
        return 1;
    }
    printf("Received secure message: %s\n", msg.data);
    if (strcmp(secure_msg, msg.data) != 0) {
        printf("Secure message mismatch!\n");
        anet_ws_message_free(&msg);
        anet_sync_ws_destroy(ws);
        anet_cleanup();
        return 1;
    }
    anet_ws_message_free(&msg);

    if (anet_sync_ws_send(ws, ANET_WS_BINARY, binary_data, sizeof(binary_data)) != ANET_OK) {
        printf("Error sending binary message\n");
        anet_sync_ws_destroy(ws);
        anet_cleanup();
        return 1;
    }

    // 接收二进制回显
    if (anet_sync_ws_recv(ws, &msg) != ANET_OK) {
        printf("Error receiving binary message\n");
        anet_sync_ws_destroy(ws);
        anet_cleanup();
        return 1;
    }

    printf("Received binary message: ");
    for (size_t i = 0; i < msg.len; i++) {
        printf("%02x ", (unsigned char)msg.data[i]);
    }
    printf("\n");

    if (msg.len != sizeof(binary_data) || memcmp(msg.data, binary_data, sizeof(binary_data)) != 0) {
        printf("Binary message mismatch!\n");
        anet_ws_message_free(&msg);
        anet_sync_ws_destroy(ws);
        anet_cleanup();
        return 1;
    }
    anet_ws_message_free(&msg);

    // 多轮消息测试
    printf("Testing multiple message exchanges...\n");
    for (int i = 0; i < 5; i++) {
        char message[64];
        snprintf(message, sizeof(message), "Message %d from client", i);

        if (anet_sync_ws_send(ws, ANET_WS_TEXT, message, strlen(message)) != ANET_OK) {
            printf("Error sending message %d\n", i);
            anet_sync_ws_destroy(ws);
            anet_cleanup();
            return 1;
        }

        if (anet_sync_ws_recv(ws, &msg) != ANET_OK) {
            printf("Error receiving message %d\n", i);
            anet_sync_ws_destroy(ws);
            anet_cleanup();
            return 1;
        }

        printf("Round %d: %s\n", i, msg.data);
        if (strcmp(message, msg.data) != 0) {
            printf("Message mismatch in round %d!\n", i);
            anet_ws_message_free(&msg);
            anet_sync_ws_destroy(ws);
            anet_cleanup();
            return 1;
        }
        anet_ws_message_free(&msg);
    }

    // 关闭安全连接
    anet_sync_ws_close(ws);
    anet_sync_ws_destroy(ws);

    printf("Sync WebSocket test completed successfully\n");
    
    // 清理
    anet_cleanup();
    
    return 0;
}