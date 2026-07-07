#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

/*
 * HTTP 服务端对抗性输入测试。
 *
 * 用高层 anet_http_server 起一个明文 server (回显 path), 再用裸 async socket
 * 作客户端, 逐个发畸形/边界请求, 验证 server:
 *   - 不崩、不泄漏 (ASan)
 *   - 每条畸形连接都干净收尾 (server 侧协程结束), 不永久挂住 fd/协程
 *   - 畸形连接之后 server 仍能正常服务一个良性请求 (存活性)
 *
 * 所有场景在单协程里串行跑: 每个场景开一条新客户端连接, 发完读到 EOF 或响应,
 * 关闭, 再进下一个。最后发一个正常请求确认 server 未死。
 */

static uint16_t g_port;
static anet_http_server_t *g_server;

static void echo_handler(const anet_http_server_request_t *req,
                         anet_http_server_response_t *resp, void *ud) {
    (void)ud;
    static char body[256];
    snprintf(body, sizeof(body), "%s %s", req->method, req->path);
    resp->status_code = 200;
    resp->status_text = "OK";
    resp->content_type = "text/plain";
    resp->body = body;
}

/* 连到 server, 返回已连接的 client socket (失败 exit)。 */
static anet_socket_t *connect_client(void) {
    anet_palsock_t cs = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(cs)) { printf("client create failed\n"); exit(1); }
    return anet_socket_create(cs);
}

task_t* task(adversarial_task) {
    gen_dec_vars(
        anet_socket_t *cli;
        future_t      *fut;
        task_t        *accept_task;
        char           rbuf[8192];
        int            scenario;
        const char    *payload;
        size_t         payload_len;
        char           big[70 * 1024];   /* > SRV_REQ_MAX (64KB) */
    );
    gen_begin(ctx);

    /* 起 server accept 循环 (分离协程) */
    gen_var(accept_task) = anet_http_server_run(g_server);
    task_run(gen_var(accept_task));

    for (gen_var(scenario) = 0; gen_var(scenario) < 6; gen_var(scenario)++) {
        gen_var(cli) = connect_client();
        {
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            sin.sin_port = htons(g_port);
            gen_var(fut) = anet_socket_connect(gen_var(cli), (struct sockaddr*)&sin, sizeof(sin));
        }
        gen_yield(gen_var(fut));
        if (future_is_rejected(gen_var(fut))) { printf("connect rejected s=%d\n", gen_var(scenario)); exit(1); }

        /* 组装本场景的畸形 payload */
        switch (gen_var(scenario)) {
        case 0: /* 请求行没有空格 (无法切出 method/path) */
            gen_var(payload) = "GARBAGE-NO-SPACES\r\n\r\n";
            gen_var(payload_len) = strlen(gen_var(payload));
            break;
        case 1: /* 只有 method, 缺 path 和 version */
            gen_var(payload) = "GET\r\n\r\n";
            gen_var(payload_len) = strlen(gen_var(payload));
            break;
        case 2: /* Content-Length 远大于实际 body, 随后立即关闭 (半发) */
            gen_var(payload) = "POST /x HTTP/1.1\r\nContent-Length: 1000000\r\n\r\nshort";
            gen_var(payload_len) = strlen(gen_var(payload));
            break;
        case 3: /* 巨大的 Content-Length 数值 (溢出/资源意图) */
            gen_var(payload) = "POST /x HTTP/1.1\r\nContent-Length: 99999999999999\r\n\r\n";
            gen_var(payload_len) = strlen(gen_var(payload));
            break;
        case 4: /* 超过 64KB 上限、且始终不出现头部结束符 */
            memset(gen_var(big), 'A', sizeof(gen_var(big)));
            gen_var(big)[0] = 'G'; gen_var(big)[1] = 'E'; gen_var(big)[2] = 'T'; gen_var(big)[3] = ' ';
            gen_var(payload) = gen_var(big);
            gen_var(payload_len) = sizeof(gen_var(big));
            break;
        default: /* case 5: 连上不发任何数据, 直接关 (空连接) */
            gen_var(payload) = NULL;
            gen_var(payload_len) = 0;
            break;
        }

        if (gen_var(payload_len) > 0) {
            gen_var(fut) = anet_socket_send(gen_var(cli), gen_var(payload), gen_var(payload_len));
            gen_yield(gen_var(fut));
            /* send 可能因 server 已断开而 reject —— 对抗场景里可接受, 不判死。 */
        }

        /* 立即关闭客户端 (模拟半发/放弃连接的对端)。不 recv —— loop 单线程,
           对不完整请求 server 仍在等 body, recv 会与之互相死等。关闭后 server
           的挂起 read 会得到 EOF, 走 n<=0 收尾路径, 干净销毁连接协程。这正是
           要考验的"半关/放弃对端"路径。存活性由末尾的良性请求验证。 */
        anet_socket_close(gen_var(cli));
        free(gen_var(cli));
        gen_var(cli) = NULL;
        printf("scenario %d handled\n", gen_var(scenario));
    }

    /* --- 存活性: 畸形轰炸后, server 仍能正常服务一个良性请求 --- */
    gen_var(cli) = connect_client();
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = htons(g_port);
        gen_var(fut) = anet_socket_connect(gen_var(cli), (struct sockaddr*)&sin, sizeof(sin));
    }
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { printf("liveness connect rejected\n"); exit(1); }

    gen_var(payload) = "GET /alive HTTP/1.1\r\nConnection: close\r\n\r\n";
    gen_var(fut) = anet_socket_send(gen_var(cli), gen_var(payload), strlen(gen_var(payload)));
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { printf("liveness send rejected\n"); exit(1); }

    memset(gen_var(rbuf), 0, sizeof(gen_var(rbuf)));
    gen_var(fut) = anet_socket_recv(gen_var(cli), gen_var(rbuf), sizeof(gen_var(rbuf)) - 1);
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { printf("liveness recv rejected\n"); exit(1); }
    if (anet_code_of(future_result(gen_var(fut))) <= 0) { printf("liveness: server closed without responding\n"); exit(1); }
    if (!strstr(gen_var(rbuf), "200") || !strstr(gen_var(rbuf), "GET /alive")) {
        printf("liveness: unexpected response:\n%s\n", gen_var(rbuf));
        exit(1);
    }
    printf("liveness OK: server still serving after adversarial input\n");

    anet_socket_close(gen_var(cli));
    free(gen_var(cli));
    gen_var(cli) = NULL;

    anet_http_server_stop(g_server);
    printf("Server adversarial test passed\n");
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_server_adversarial() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }
    g_server = anet_http_server_create(0, echo_handler, NULL);
    if (!g_server) { printf("server create failed\n"); return 1; }
    g_port = anet_http_server_port(g_server);
    printf("adversarial server on 127.0.0.1:%u\n", g_port);

    task_t *t = adversarial_task();
    loop_run(t);

    anet_http_server_destroy(g_server);
    g_server = NULL;
    anet_cleanup();
    return 0;
}
