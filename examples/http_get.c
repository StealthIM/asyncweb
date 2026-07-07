/*
 * asyncweb 最小示例: 同步 HTTP GET 客户端。
 *
 * 同步 API 会自己驱动事件循环直到请求完成, 调用方无需管 loop。
 *
 * 构建见 examples/CMakeLists.txt。运行:
 *   ./http_get http://postman-echo.com/get
 */
#include <stdio.h>
#include <asyncweb/asyncweb.h>

int main(int argc, char **argv) {
    const char *url = (argc > 1) ? argv[1] : "http://postman-echo.com/get";

    if (anet_init() != ANET_OK) {
        fprintf(stderr, "anet_init failed\n");
        return 1;
    }

    anet_sync_http_response_t resp;
    if (anet_sync_http_get(url, &resp) != ANET_OK) {
        fprintf(stderr, "GET %s failed\n", url);
        anet_cleanup();
        return 1;
    }

    printf("Status: %d %s\n", resp.status_code, resp.status_text);
    printf("--- body (%zu bytes) ---\n%s\n", resp.body_len, resp.body ? resp.body : "");

    anet_sync_http_response_free(&resp);
    anet_cleanup();
    return 0;
}
