#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

/*
 * HTTP 服务端并发多连接测试。
 *
 * server 模型是"单 accept 循环 + 每连接分离协程", 但从没测过 N 个并发连接。
 * 本测试同时发起 N 个客户端 (都在同一 loop 里并发推进), 每个各发一个 GET、
 * 收响应、关闭。验证:
 *   - N 个连接全部成功拿到正确响应
 *   - 无 fd 泄漏 (跑前/跑后比对 /proc/self/fd 计数)
 *   - 无内存泄漏 (ASan)
 *   - server stop 后 accept 循环干净退出
 *
 * 协调方式: coordinator task 起 N 个 client 子 task (task_run 分离), 再轮询
 * 一个全局完成计数, 归零后 stop server + loop_stop。client 子 task 完成时
 * 递减计数。
 */

#define N_CLIENTS 64

static uint16_t g_port;
static anet_http_server_t *g_server;
static int g_pending;      /* 未完成的 client 数 */
static int g_failures;     /* 出错的 client 数 */

static void echo_handler(const anet_http_server_request_t *req,
                         anet_http_server_response_t *resp, void *ud) {
    (void)ud;
    static char body[128];
    snprintf(body, sizeof(body), "%s %s", req->method, req->path);
    resp->status_code = 200;
    resp->status_text = "OK";
    resp->content_type = "text/plain";
    resp->body = body;
}

/* 单个客户端: connect -> GET -> recv -> close。完成后递减 g_pending。 */
task_t* task(client_task) {
    gen_dec_vars(
        anet_socket_t *cli;
        future_t      *fut;
        char           rbuf[4096];
        char           req[64];
    );
    gen_begin(ctx);

    {
        anet_palsock_t cs = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
        if (!anet_palsock_is_valid(cs)) { g_failures++; goto done; }
        gen_var(cli) = anet_socket_create(cs);
    }
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = htons(g_port);
        gen_var(fut) = anet_socket_connect(gen_var(cli), (struct sockaddr*)&sin, sizeof(sin));
    }
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { g_failures++; goto close_done; }

    snprintf(gen_var(req), sizeof(gen_var(req)), "GET /c HTTP/1.1\r\nConnection: close\r\n\r\n");
    gen_var(fut) = anet_socket_send(gen_var(cli), gen_var(req), strlen(gen_var(req)));
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { g_failures++; goto close_done; }

    memset(gen_var(rbuf), 0, sizeof(gen_var(rbuf)));
    gen_var(fut) = anet_socket_recv(gen_var(cli), gen_var(rbuf), sizeof(gen_var(rbuf)) - 1);
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut)) ||
        anet_code_of(future_result(gen_var(fut))) <= 0 ||
        !strstr(gen_var(rbuf), "200") ||
        !strstr(gen_var(rbuf), "GET /c")) {
        g_failures++;
    }

close_done:
    anet_socket_close(gen_var(cli));
    free(gen_var(cli));
    gen_var(cli) = NULL;
done:
    g_pending--;
    gen_return(NULL);
    gen_end(NULL);
}

task_t* task(coordinator_task) {
    gen_dec_vars(
        int      i;
        task_t  *accept_task;
        task_t  *ct;
    );
    gen_begin(ctx);

    gen_var(accept_task) = anet_http_server_run(g_server);
    task_run(gen_var(accept_task));

    /* 一次性并发发起 N 个 client (全部 post 到 loop, 并发推进) */
    g_pending = N_CLIENTS;
    for (gen_var(i) = 0; gen_var(i) < N_CLIENTS; gen_var(i)++) {
        gen_var(ct) = client_task();
        if (!gen_var(ct)) { g_pending--; g_failures++; continue; }
        task_run(gen_var(ct));
    }

    /* 轮询等所有 client 完成 */
    while (g_pending > 0) {
        gen_yield(async_sleep(5));
    }

    anet_http_server_stop(g_server);
    /* 给 accept 循环一拍时间处理 self-connect 唤醒并退出 */
    gen_yield(async_sleep(10));

    if (g_failures > 0) {
        printf("concurrent: %d/%d clients failed\n", g_failures, N_CLIENTS);
        exit(1);
    }
    printf("concurrent: all %d clients OK\n", N_CLIENTS);
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

static int count_fds(void) {
    /* Linux: /proc/self/fd 里的条目数 (含 opendir 自身的一个 fd, 前后一致可抵消)。 */
    FILE *p = popen("ls /proc/self/fd 2>/dev/null | wc -l", "r");
    if (!p) return -1;
    int n = -1;
    if (fscanf(p, "%d", &n) != 1) n = -1;
    pclose(p);
    return n;
}

int test_server_concurrent() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }
    g_server = anet_http_server_create(0, echo_handler, NULL);
    if (!g_server) { printf("server create failed\n"); return 1; }
    g_port = anet_http_server_port(g_server);
    g_failures = 0;
    printf("concurrent server on 127.0.0.1:%u, %d clients\n", g_port, N_CLIENTS);

    int fds_before = count_fds();

    task_t *t = coordinator_task();
    loop_run(t);

    anet_http_server_destroy(g_server);
    g_server = NULL;
    anet_cleanup();

    int fds_after = count_fds();
    printf("fds before=%d after=%d\n", fds_before, fds_after);
    if (fds_before >= 0 && fds_after >= 0 && fds_after > fds_before) {
        printf("fd LEAK detected: %d -> %d\n", fds_before, fds_after);
        return 1;
    }
    printf("Server concurrent test passed\n");
    return 0;
}
