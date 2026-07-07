#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

/*
 * 高层 HTTP 服务端端到端测试:
 *   - anet_http_server 起一个 loopback 服务器,handler 回显 path
 *   - 用异步 HTTP 客户端向它发 GET / POST
 *   - 校验响应,再 stop + destroy 服务器,验证 accept 循环干净退出
 */

static anet_http_server_t *g_server;

static void echo_handler(const anet_http_server_request_t *req,
                         anet_http_server_response_t *resp,
                         void *userdata) {
    (void)userdata;
    static char body[512];
    if (req->body && req->body_len > 0) {
        snprintf(body, sizeof(body), "%s %s body=%.*s",
                 req->method, req->path, (int)req->body_len, req->body);
    } else {
        snprintf(body, sizeof(body), "%s %s", req->method, req->path);
    }
    resp->status_code = 200;
    resp->status_text = "OK";
    resp->content_type = "text/plain";
    resp->body = body;
}

task_t* task(server_client_task) {
    gen_dec_vars(
        task_t *accept_task;
        task_t *req_task;
        anet_async_http_response_t response;
        char url[128];
        void *result;
    );
    gen_begin(ctx);

    /* 起服务器 accept 循环 (分离协程) */
    gen_var(accept_task) = anet_http_server_run(g_server);
    task_run(gen_var(accept_task));

    /* --- GET --- */
    snprintf(gen_var(url), sizeof(gen_var(url)),
             "http://127.0.0.1:%u/hello", anet_http_server_port(g_server));
    gen_var(req_task) = anet_async_http_get(gen_var(url), &gen_var(response));
    gen_yield_from_task(gen_var(req_task));
    gen_var(result) = future_result(gen_var(req_task)->future);
    if (gen_var(result) == (void*)ANET_ERR) { printf("GET failed\n"); exit(1); }
    printf("GET status=%d body=%s\n", gen_var(response).status_code, gen_var(response).body);
    if (gen_var(response).status_code != 200 ||
        strcmp(gen_var(response).body, "GET /hello") != 0) {
        printf("GET mismatch\n"); exit(1);
    }
    anet_http_response_free(&gen_var(response));

    /* --- POST --- */
    snprintf(gen_var(url), sizeof(gen_var(url)),
             "http://127.0.0.1:%u/submit", anet_http_server_port(g_server));
    gen_var(req_task) = anet_async_http_post(gen_var(url), "text/plain", "payload", &gen_var(response));
    gen_yield_from_task(gen_var(req_task));
    gen_var(result) = future_result(gen_var(req_task)->future);
    if (gen_var(result) == (void*)ANET_ERR) { printf("POST failed\n"); exit(1); }
    printf("POST status=%d body=%s\n", gen_var(response).status_code, gen_var(response).body);
    if (gen_var(response).status_code != 200 ||
        strcmp(gen_var(response).body, "POST /submit body=payload") != 0) {
        printf("POST mismatch\n"); exit(1);
    }
    anet_http_response_free(&gen_var(response));

    /* 停服务器,唤醒并退出 accept 循环 */
    anet_http_server_stop(g_server);

    printf("HTTP server test passed\n");
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_http_server() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }

    g_server = anet_http_server_create(0, echo_handler, NULL);
    if (!g_server) { printf("server create failed\n"); return 1; }
    printf("server listening on 127.0.0.1:%u\n", anet_http_server_port(g_server));

    task_t *t = server_client_task();
    loop_run(t);

    anet_http_server_destroy(g_server);
    g_server = NULL;
    anet_cleanup();
    return 0;
}
