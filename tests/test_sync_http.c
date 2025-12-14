#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "asyncweb.h"

int test_sync_http() {
    // 初始化网络库
    if (anet_init() != ANET_OK) {
        printf("Network initialization failed\n");
        return 1;
    }
    
    // 创建并运行主任务
    anet_sync_http_response_t response;
    int result;

    printf("Testing sync HTTP GET request\n");

    // 调用同步HTTP API
    result = anet_sync_http_get("http://postman-echo.com/get", &response);
    if (result != ANET_OK) {
        printf("HTTP GET request failed\n");
        exit(1);
    }

    printf("Status: %d %s\n", response.status_code, response.status_text);
    printf("Headers:\n%s\n", response.headers);
    printf("Body:\n%s\n", response.body);

    // 释放资源
    anet_sync_http_response_free(&response);

    // 测试HTTPS GET请求
    printf("\nTesting sync HTTPS GET request\n");

    result = anet_sync_http_get("https://postman-echo.com/get", &response);
    if (result != ANET_OK) {
        printf("HTTPS GET request failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("Status: %d %s\n", response.status_code, response.status_text);
    printf("Headers:\n%s\n", response.headers);
    printf("Body (first 200 chars):\n%.200s%s\n", response.body, strlen(response.body) > 200 ? "..." : "");

    // 释放资源
    anet_sync_http_response_free(&response);

    // 测试HTTPS POST请求
    printf("\nTesting sync HTTPS POST request\n");
    const char *https_body = "{\"secure\": \"Hello from asyncweb HTTPS\"}";

    result = anet_sync_http_post("https://postman-echo.com/post", "application/json", https_body, &response);
    if (result != ANET_OK) {
        printf("HTTPS POST request failed\n");
        exit(1);
    }

    printf("Status: %d %s\n", response.status_code, response.status_text);
    printf("Body (first 200 chars):\n%.200s%s\n", response.body, strlen(response.body) > 200 ? "..." : "");

    // 释放资源
    anet_sync_http_response_free(&response);

    printf("Sync HTTP/HTTPS test completed successfully\n");
    
    // 清理
    anet_cleanup();
    
    return 0;
}