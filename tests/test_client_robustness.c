#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

/*
 * HTTP 客户端健壮性测试。
 *
 * 起一个"恶意"裸 server (raw async socket): 每次 accept 一条连接, 读掉请求,
 * 回一段畸形响应再关闭。用真正的异步 HTTP 客户端 (anet_async_http_get) 打它,
 * 逐个场景验证客户端:
 *   - 不崩、不越界读、不泄漏 (ASan)
 *   - 对畸形响应返回 ANET_ERR 或容错解析, 但绝不 OOB/hang
 *
 * 场景:
 *   0 有头无 \r\n\r\n 终止符, 直接关 (最易触发 strstr 越界)
 *   1 状态行是垃圾 (无空格)
 *   2 Content-Length 远大于实际 body, 随后关闭
 *   3 空响应 (0 字节直接关)
 *   4 一个正常响应 (存活性: 客户端在畸形轰炸后仍能正常解析)
 */

#define N_SCENARIOS 5

static anet_listener_t *g_listener;
static uint16_t         g_port;
static int              g_scenario;

/* 恶意 server: accept 一条连接, 读掉请求, 回场景对应的畸形字节, 关闭。 */
task_t* task(evil_server_task) {
    gen_dec_vars(
        future_t      *fut;
        anet_socket_t *conn;
        char           reqbuf[2048];
        const char    *resp;
        size_t         resp_len;
    );
    gen_begin(ctx);

    gen_var(fut) = anet_socket_accept(g_listener);
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { gen_return(NULL); }
    gen_var(conn) = (anet_socket_t*)future_result(gen_var(fut));

    /* 读掉客户端请求 (一次即可, 不关心内容) */
    gen_var(fut) = anet_socket_recv(gen_var(conn), gen_var(reqbuf), sizeof(gen_var(reqbuf)));
    gen_yield(gen_var(fut));

    switch (g_scenario) {
    case 0: /* 有头部但无 \r\n\r\n 终止符 */
        gen_var(resp) = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Trunc: yes";
        break;
    case 1: /* 垃圾状态行 (无空格) */
        gen_var(resp) = "GARBAGE-STATUS-LINE-NO-SPACES\r\n\r\n";
        break;
    case 2: /* Content-Length 远超实际 body */
        gen_var(resp) = "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nshort";
        break;
    case 3: /* 空响应 */
        gen_var(resp) = NULL;
        break;
    default: /* case 4: 正常响应 */
        gen_var(resp) = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        break;
    }

    if (gen_var(resp)) {
        gen_var(resp_len) = strlen(gen_var(resp));
        gen_var(fut) = anet_socket_send(gen_var(conn), gen_var(resp), gen_var(resp_len));
        gen_yield(gen_var(fut));
    }

    anet_socket_close(gen_var(conn));
    free(gen_var(conn));
    gen_return(NULL);
    gen_end(NULL);
}

task_t* task(client_robustness_task) {
    gen_dec_vars(
        int                          i;
        task_t                      *evil;
        task_t                      *req;
        anet_async_http_response_t   resp;
        char                         url[64];
        void                        *result;
    );
    gen_begin(ctx);

    for (gen_var(i) = 0; gen_var(i) < N_SCENARIOS; gen_var(i)++) {
        g_scenario = gen_var(i);

        /* 起一次性恶意 server (分离协程), 再打它 */
        gen_var(evil) = evil_server_task();
        task_run(gen_var(evil));

        memset(&gen_var(resp), 0, sizeof(gen_var(resp)));
        snprintf(gen_var(url), sizeof(gen_var(url)), "http://127.0.0.1:%u/x", g_port);
        gen_var(req) = anet_async_http_get(gen_var(url), &gen_var(resp));
        gen_yield_from_task(gen_var(req));

        gen_var(result) = future_result(gen_var(req)->future);
        if (gen_var(i) == 4) {
            /* 存活性: 正常响应必须解析成功 */
            if (anet_status_of(gen_var(result)) != ANET_OK ||
                gen_var(resp).status_code != 200 ||
                !gen_var(resp).body || strcmp(gen_var(resp).body, "hello") != 0) {
                printf("scenario 4 (valid) mismatch: status=%d body=%s\n",
                       gen_var(resp).status_code, gen_var(resp).body ? gen_var(resp).body : "(null)");
                exit(1);
            }
            printf("scenario 4 (valid) OK\n");
        } else {
            /* 畸形: 只要没崩/没越界即可, 结果 OK/ERR 都接受 */
            printf("scenario %d handled (status=%s)\n", gen_var(i),
                   anet_status_of(gen_var(result)) == ANET_OK ? "OK" : "ERR");
        }
        anet_http_response_free(&gen_var(resp));
    }

    printf("Client robustness test passed\n");
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_client_robustness() {
    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }

    anet_palsock_t ls = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(ls)) { printf("listen create failed\n"); return 1; }
    anet_palsock_set_reuseaddr(ls, 1);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    if (anet_palsock_bind(ls, (struct sockaddr*)&sin, sizeof(sin)) != 0) { printf("bind failed\n"); return 1; }
    if (anet_palsock_listen(ls, 8) != 0) { printf("listen failed\n"); return 1; }
    int blen = sizeof(sin);
    anet_palsock_getsockname(ls, (struct sockaddr*)&sin, &blen);
    g_port = ntohs(sin.sin_port);
    g_listener = anet_listener_create(ls);
    printf("evil server on 127.0.0.1:%u\n", g_port);

    task_t *t = client_robustness_task();
    loop_run(t);

    anet_listener_close(g_listener);
    free(g_listener);
    anet_cleanup();
    return 0;
}
