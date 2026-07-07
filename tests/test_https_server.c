#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_WIN32) || defined(_WIN64)
#  include <direct.h>
#  define make_dir(p) _mkdir(p)
#  define change_dir(p) _chdir(p)
#else
#  include <unistd.h>
#  define make_dir(p) mkdir((p), 0700)
#  define change_dir(p) chdir(p)
#endif
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>
#include "test_certs.h"

/*
 * HTTPS 服务端端到端测试:
 *   - 用预生成的自签名证书 (SAN IP:127.0.0.1),与 TLS 后端解耦
 *   - anet_http_server 启用 TLS 后监听 loopback
 *   - 用真实的异步 HTTPS 客户端 (完整校验:cert 链 + hostname) 请求
 *   - 在临时子目录里跑,把证书拷进去作 ./cacert.pem,不动真实 CA 包
 */

static anet_http_server_t *g_server;

static void echo_handler(const anet_http_server_request_t *req,
                         anet_http_server_response_t *resp,
                         void *userdata) {
    (void)userdata;
    static char body[256];
    snprintf(body, sizeof(body), "%s %s", req->method, req->path);
    resp->status_code = 200;
    resp->status_text = "OK";
    resp->content_type = "text/plain";
    resp->body = body;
}

task_t* task(https_client_task) {
    gen_dec_vars(
        task_t *accept_task;
        task_t *req_task;
        anet_async_http_response_t response;
        char url[128];
        void *result;
    );
    gen_begin(ctx);

    gen_var(accept_task) = anet_http_server_run(g_server);
    task_run(gen_var(accept_task));

    snprintf(gen_var(url), sizeof(gen_var(url)),
             "https://127.0.0.1:%u/secure", anet_http_server_port(g_server));
    gen_var(req_task) = anet_async_http_get(gen_var(url), &gen_var(response));
    gen_yield_from_task(gen_var(req_task));
    gen_var(result) = future_result(gen_var(req_task)->future);
    if (gen_var(result) == (void*)ANET_ERR) { printf("HTTPS GET failed\n"); exit(1); }
    printf("HTTPS GET status=%d body=%s\n",
           gen_var(response).status_code, gen_var(response).body);
    if (gen_var(response).status_code != 200 ||
        strcmp(gen_var(response).body, "GET /secure") != 0) {
        printf("HTTPS response mismatch\n"); exit(1);
    }
    anet_http_response_free(&gen_var(response));

    anet_http_server_stop(g_server);

    printf("HTTPS server test passed\n");
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_https_server() {
    /* 在临时子目录里跑:把预生成证书拷进去作 ./cacert.pem,不污染仓库工作树 */
    make_dir("tls_test_tmp");
    if (change_dir("tls_test_tmp") != 0) { printf("chdir failed\n"); return 1; }

    if (copy_test_certs() != 0) { printf("copy certs failed\n"); return 1; }

    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }

    g_server = anet_http_server_create(0, echo_handler, NULL);
    if (!g_server) { printf("server create failed\n"); return 1; }
    if (anet_http_server_use_tls(g_server, "cert.pem", "key.pem") != 0) {
        printf("use_tls failed\n"); return 1;
    }
    printf("https server listening on 127.0.0.1:%u\n", anet_http_server_port(g_server));

    task_t *t = https_client_task();
    loop_run(t);

    anet_http_server_destroy(g_server);
    g_server = NULL;
    anet_cleanup();
    return 0;
}
