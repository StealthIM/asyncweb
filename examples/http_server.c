/*
 * asyncweb 最小示例: 明文 HTTP 服务端。
 *
 * 监听 127.0.0.1:8080, 每个请求回显 "METHOD PATH"。accept 循环本身是一个
 * task, 用 loop_run 驱动它直到服务器 stop —— 这里没有 stop, 所以会一直服务
 * (Ctrl-C 退出)。
 *
 *   ./http_server
 *   curl http://127.0.0.1:8080/hello   ->  GET /hello
 *
 * 注意: 本例绑定 loopback 且无鉴权 —— 仅供本地演示, 不要直接暴露到网络。
 */
#include <stdio.h>
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

static void echo_handler(const anet_http_server_request_t *req,
                         anet_http_server_response_t *resp,
                         void *userdata) {
    (void)userdata;
    static char body[512];
    snprintf(body, sizeof(body), "%s %s", req->method, req->path);
    resp->status_code = 200;
    resp->status_text = "OK";
    resp->content_type = "text/plain";
    resp->body = body;      /* body_len=0 => 用 strlen(body) */
}

int main(void) {
    if (anet_init() != ANET_OK) {
        fprintf(stderr, "anet_init failed\n");
        return 1;
    }

    anet_http_server_t *server = anet_http_server_create(8080, echo_handler, NULL);
    if (!server) {
        fprintf(stderr, "server create failed (port in use?)\n");
        anet_cleanup();
        return 1;
    }
    printf("listening on http://127.0.0.1:%u  (Ctrl-C to quit)\n",
           anet_http_server_port(server));

    /* 驱动 accept 循环 task 直到服务器停止。 */
    loop_run(anet_http_server_run(server));

    anet_http_server_destroy(server);
    anet_cleanup();
    return 0;
}
