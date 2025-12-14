#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libcoro.h"
#include "asyncweb.h"

task_t* task(sync_http_test_task) {
    gen_dec_vars(
        sync_http_response_t response;
        int result;
    );
    gen_begin(ctx);
    
    printf("Testing sync HTTP GET request\n");
    
    // 调用同步HTTP API
    gen_var(result) = sync_http_get("http://postman-echo.com/get", &gen_var(response));
    if (gen_var(result) != 0) {
        printf("HTTP GET request failed\n");
        gen_return(1);
    }
    
    printf("Status: %d %s\n", gen_var(response).status_code, gen_var(response).status_text);
    printf("Headers:\n%s\n", gen_var(response).headers);
    printf("Body:\n%s\n", gen_var(response).body);
    
    // 释放资源
    sync_http_response_free(&gen_var(response));
    
    printf("Sync HTTP test completed successfully\n");
    loop_stop();
    gen_return(0);
    
    gen_end(NULL);
}

int test_sync_http() {
    // 初始化网络库
    if (anet_init() != ANET_OK) {
        printf("Network initialization failed\n");
        return 1;
    }
    
    // 创建并运行主任务
    task_t* maintask = sync_http_test_task();
    loop_run(maintask);
    
    // 清理
    anet_cleanup();
    
    return 0;
}