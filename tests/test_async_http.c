#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libcoro.h"
#include "asyncweb.h"

task_t* task(async_http_test_task) {
    gen_dec_vars(
        async_http_response_t response;
        task_t *task;
        void *result;
    );
    gen_begin(ctx);
    
    printf("Testing async HTTP GET request\n");
    
    // 调用异步HTTP API
    gen_var(task) = async_http_get("http://postman-echo.com/get", &gen_var(response));
    gen_yield_from_task(gen_var(task));

    gen_var(result) = future_result(gen_var(task)->future);
    if (gen_var(result) == (void*)-1) {
        printf("HTTP GET request failed\n");
        gen_return(1);
    }

    printf("Status: %d %s\n", gen_var(response).status_code, gen_var(response).status_text);
    printf("Headers:\n%s\n", gen_var(response).headers);
    printf("Body:\n%s\n", gen_var(response).body);

    // 释放资源
    async_http_response_free(&gen_var(response));

    // 测试POST请求
    printf("\nTesting async HTTP POST request\n");
    const char *json_body = "{\"message\": \"Hello from asyncweb\"}";

    gen_var(task) = async_http_post("http://postman-echo.com/post", "application/json", json_body, &gen_var(response));
    gen_yield_from_task(gen_var(task));

    gen_var(result) = future_result(gen_var(task)->future);
    if (gen_var(result) == (void*)-1) {
        printf("HTTP POST request failed\n");
        gen_return(1);
    }

    printf("Status: %d %s\n", gen_var(response).status_code, gen_var(response).status_text);
    printf("Body:\n%s\n", gen_var(response).body);

    // 释放资源
    async_http_response_free(&gen_var(response));

    printf("Async HTTP test completed successfully\n");
    loop_stop();
    gen_return(0);
    
    gen_end(NULL);
}

int test_async_http() {
    // 初始化网络库
    if (anet_init() != ANET_OK) {
        printf("Network initialization failed\n");
        return 1;
    }
    
    // 创建并运行主任务
    task_t* maintask = async_http_test_task();
    loop_run(maintask);
    
    // 清理
    anet_cleanup();
    
    return 0;
}