#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libcoro.h"
#include "asyncweb.h"

task_t* task(async_ws_test_task) {
    gen_dec_vars(
        anet_async_ws_t *ws;
        anet_ws_message_t msg;
        task_t *task;
        void *result;
        int i;
        char message[64];
        unsigned char binary_data[5];
        const char *ws_msg;
    );
    gen_begin(ctx);
    gen_var(binary_data)[0] = 0x01;
    gen_var(binary_data)[1] = 0x02;
    gen_var(binary_data)[2] = 0x03;
    gen_var(binary_data)[3] = 0x04;
    gen_var(binary_data)[4] = 0x05;
    gen_var(ws_msg) = "Hello, WebSocket!";
    
    printf("Testing async WebSocket connection to wss://echo.websocket.org\n");
    
    // 测试普通WebSocket连接
    gen_var(task) = anet_async_ws_connect("wss://echo.websocket.org", &gen_var(ws));
    gen_yield_from_task(gen_var(task));

    gen_var(result) = future_result(gen_var(task)->future);
    if (gen_var(result) == NULL) {
        printf("WebSocket connect failed\n");
        exit(1);
        gen_return(1);
    }

    printf("Connected to WebSocket server!\n");


    gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
    gen_yield_from_task(gen_var(task));

    gen_var(result) = future_result(gen_var(task)->future);
    if (gen_var(result) == (void*)-1) {
        printf("Error receiving message\n");
        anet_async_ws_destroy(gen_var(ws));
        exit(1);
        gen_return(1);
    }

    // 发送文本消息
    gen_var(task) = anet_async_ws_send(gen_var(ws), ANET_WS_TEXT, gen_var(ws_msg), strlen(gen_var(ws_msg)));
    gen_yield_from_task(gen_var(task));

    gen_var(result) = future_result(gen_var(task)->future);
    if (gen_var(result) == (void*)-1) {
        printf("Error sending text message\n");
        anet_async_ws_destroy(gen_var(ws));
        exit(1);
        gen_return(1);
    }

    // 接收回显消息
    gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
    gen_yield_from_task(gen_var(task));

    gen_var(result) = future_result(gen_var(task)->future);
    if (gen_var(result) == (void*)-1) {
        printf("Error receiving message\n");
        anet_async_ws_destroy(gen_var(ws));
        exit(1);
        gen_return(1);
    }

    printf("Received text message: %s\n", gen_var(msg).data);
    if (strcmp(gen_var(ws_msg), gen_var(msg).data) != 0) {
        printf("Message mismatch!\n");
        anet_ws_message_free(&gen_var(msg));
        anet_async_ws_destroy(gen_var(ws));
        exit(1);
        gen_return(1);
    }
    anet_ws_message_free(&gen_var(msg));

    // 发送二进制消息
    gen_var(task) = anet_async_ws_send(gen_var(ws), ANET_WS_BINARY, gen_var(binary_data), sizeof(gen_var(binary_data)));
    gen_yield_from_task(gen_var(task));

    gen_var(result) = future_result(gen_var(task)->future);
    if (gen_var(result) == (void*)-1) {
        printf("Error sending binary message\n");
        anet_async_ws_destroy(gen_var(ws));
        exit(1);
        gen_return(1);
    }

    // 接收二进制回显
    gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
    gen_yield_from_task(gen_var(task));

    gen_var(result) = future_result(gen_var(task)->future);
    if (gen_var(result) == (void*)-1) {
        printf("Error receiving binary message\n");
        anet_async_ws_destroy(gen_var(ws));
        exit(1);
        gen_return(1);
    }

    printf("Received binary message: ");
    for (size_t i = 0; i < gen_var(msg).len; i++) {
        printf("%02x ", (unsigned char)gen_var(msg).data[i]);
    }
    printf("\n");

    if (gen_var(msg).len != sizeof(gen_var(binary_data)) || 
        memcmp(gen_var(msg).data, gen_var(binary_data), sizeof(gen_var(binary_data))) != 0) {
        printf("Binary message mismatch!\n");
        anet_ws_message_free(&gen_var(msg));
        anet_async_ws_destroy(gen_var(ws));
        exit(1);
        gen_return(1);
    }
    anet_ws_message_free(&gen_var(msg));

    // 多轮消息测试
    printf("Testing multiple message exchanges...\n");
    for (gen_var(i) = 0; gen_var(i) < 5; gen_var(i)++) {
        snprintf(gen_var(message), sizeof(gen_var(message)), "Message %d from client", gen_var(i));
        
        gen_var(task) = anet_async_ws_send(gen_var(ws), ANET_WS_TEXT, gen_var(message), strlen(gen_var(message)));
        gen_yield_from_task(gen_var(task));

        gen_var(result) = future_result(gen_var(task)->future);
        if (gen_var(result) == (void*)-1) {
            printf("Error sending message %d\n", gen_var(i));
            anet_async_ws_destroy(gen_var(ws));
            exit(1);
            gen_return(1);
        }
        
        gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
        gen_yield_from_task(gen_var(task));

        gen_var(result) = future_result(gen_var(task)->future);
        if (gen_var(result) == (void*)-1) {
            printf("Error receiving message %d\n", gen_var(i));
            anet_async_ws_destroy(gen_var(ws));
            exit(1);
            gen_return(1);
        }
        
        printf("Round %d: %s\n", gen_var(i), gen_var(msg).data);
        if (strcmp(gen_var(message), gen_var(msg).data) != 0) {
            printf("Message mismatch in round %d!\n", gen_var(i));
            anet_ws_message_free(&gen_var(msg));
            anet_async_ws_destroy(gen_var(ws));
            exit(1);
            gen_return(1);
        }
        anet_ws_message_free(&gen_var(msg));
    }

    // 关闭连接
    gen_var(task) = anet_async_ws_close(gen_var(ws));
    gen_yield_from_task(gen_var(task));
    anet_async_ws_destroy(gen_var(ws));
    
    gen_end(NULL);
}

int test_async_ws() {
    // 初始化网络库
    if (anet_init() != ANET_OK) {
        printf("Network initialization failed\n");
        return 1;
    }
    
    // 创建并运行主任务
    task_t* maintask = async_ws_test_task();
    loop_run(maintask);
    
    // 清理
    anet_cleanup();
    
    return 0;
}