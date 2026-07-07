/*
 * asyncweb 性能基线 (自包含, 无外部压测工具依赖)。
 *
 * 在同一进程/同一 loop 里起 asyncweb HTTP server, 再用裸 async socket 客户端
 * 压它, 量三个数:
 *   1. 顺序吞吐 (keep-alive 单连接连续 N 个请求) -> req/s + 平均延迟
 *   2. 并发吞吐 (C 条连接各发 M 个请求, 全部并发) -> req/s
 *   3. 延迟分布 (顺序场景收集每请求耗时, 报 p50/p99)
 *
 * 计时用 libcoro loop_time_ms (毫秒精度)。内存 RSS 由外层 /usr/bin/time -v 量。
 *
 * 用法: ./bench [seq_n] [conc_conns] [conc_per]
 *   默认 seq_n=20000, conc_conns=50, conc_per=400
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

/* 微秒级单调时钟 (loop_time_ms 只有毫秒精度, 高吞吐下延迟多为 0)。 */
static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000ULL);
}

static uint16_t g_port;
static anet_http_server_t *g_server;

static int SEQ_N       = 20000;
static int CONC_CONNS  = 50;
static int CONC_PER    = 400;

/* --- 并发场景共享状态 --- */
static int g_conc_pending;
static int g_conc_done_reqs;

static void bench_handler(const anet_http_server_request_t *req,
                          anet_http_server_response_t *resp, void *ud) {
    (void)ud; (void)req;
    resp->status_code = 200;
    resp->status_text = "OK";
    resp->content_type = "text/plain";
    resp->body = "pong";
    resp->body_len = 4;
}

static anet_socket_t *conn_client(void) {
    anet_palsock_t cs = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(cs)) return NULL;
    return anet_socket_create(cs);
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

/* 顺序 keep-alive: 单连接连续 SEQ_N 个请求, 记录总耗时与每请求延迟(us 粗略)。 */
task_t* task(seq_bench_task) {
    gen_dec_vars(
        anet_socket_t *cli;
        future_t      *fut;
        int            i;
        char           rbuf[4096];
        uint64_t       t0;
        uint64_t       t1;
        uint64_t       rt0;      /* 本请求开始时刻 us (必须跨 yield 存活) */
        uint64_t      *lat;      /* 每请求延迟 (us) */
        int            ok;
    );
    gen_begin(ctx);

    gen_var(cli) = conn_client();
    {
        struct sockaddr_in sin; memset(&sin,0,sizeof(sin));
        sin.sin_family=AF_INET; sin.sin_addr.s_addr=htonl(INADDR_LOOPBACK); sin.sin_port=htons(g_port);
        gen_var(fut) = anet_socket_connect(gen_var(cli),(struct sockaddr*)&sin,sizeof(sin));
    }
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { printf("seq connect failed\n"); exit(1); }

    gen_var(lat) = malloc(sizeof(uint64_t) * SEQ_N);
    gen_var(ok) = 0;
    gen_var(t0) = now_us();

    for (gen_var(i) = 0; gen_var(i) < SEQ_N; gen_var(i)++) {
        gen_var(rt0) = now_us();
        static const char *REQ = "GET /p HTTP/1.1\r\nHost: x\r\n\r\n";
        gen_var(fut) = anet_socket_send(gen_var(cli), REQ, strlen(REQ));
        gen_yield(gen_var(fut));
        if (future_is_rejected(gen_var(fut))) break;

        gen_var(fut) = anet_socket_recv(gen_var(cli), gen_var(rbuf), sizeof(gen_var(rbuf))-1);
        gen_yield(gen_var(fut));
        if (future_is_rejected(gen_var(fut)) || anet_code_of(future_result(gen_var(fut))) <= 0) break;
        gen_var(lat)[gen_var(ok)] = now_us() - gen_var(rt0);
        gen_var(ok)++;
    }

    gen_var(t1) = now_us();
    {
        uint64_t elapsed_us = gen_var(t1) - gen_var(t0);
        if (elapsed_us == 0) elapsed_us = 1;
        double rps = (double)gen_var(ok) * 1000000.0 / (double)elapsed_us;
        qsort(gen_var(lat), gen_var(ok), sizeof(uint64_t), cmp_u64);
        uint64_t p50 = gen_var(ok) ? gen_var(lat)[gen_var(ok)/2] : 0;
        uint64_t p99 = gen_var(ok) ? gen_var(lat)[(gen_var(ok)*99)/100] : 0;
        printf("[seq]  reqs=%d  elapsed=%llums  throughput=%.0f req/s  lat p50=%lluus p99=%lluus\n",
               gen_var(ok), (unsigned long long)(elapsed_us/1000), rps,
               (unsigned long long)p50, (unsigned long long)p99);
    }
    free(gen_var(lat));

    anet_socket_close(gen_var(cli));
    free(gen_var(cli));
    gen_var(cli) = NULL;

    gen_return(0);   /* 子任务: 由 master 收尾, 不自行 loop_stop */
    gen_end(NULL);
}

/* 一条并发连接: keep-alive 连发 CONC_PER 个请求, 完成后递减 pending。 */
task_t* task(conc_conn_task) {
    gen_dec_vars(
        anet_socket_t *cli;
        future_t      *fut;
        int            j;
        char           rbuf[4096];
    );
    gen_begin(ctx);

    gen_var(cli) = conn_client();
    if (!gen_var(cli)) { g_conc_pending--; gen_return(NULL); }
    {
        struct sockaddr_in sin; memset(&sin,0,sizeof(sin));
        sin.sin_family=AF_INET; sin.sin_addr.s_addr=htonl(INADDR_LOOPBACK); sin.sin_port=htons(g_port);
        gen_var(fut) = anet_socket_connect(gen_var(cli),(struct sockaddr*)&sin,sizeof(sin));
    }
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { goto done; }

    for (gen_var(j) = 0; gen_var(j) < CONC_PER; gen_var(j)++) {
        static const char *REQ = "GET /p HTTP/1.1\r\nHost: x\r\n\r\n";
        gen_var(fut) = anet_socket_send(gen_var(cli), REQ, strlen(REQ));
        gen_yield(gen_var(fut));
        if (future_is_rejected(gen_var(fut))) break;
        gen_var(fut) = anet_socket_recv(gen_var(cli), gen_var(rbuf), sizeof(gen_var(rbuf))-1);
        gen_yield(gen_var(fut));
        if (future_is_rejected(gen_var(fut)) || anet_code_of(future_result(gen_var(fut))) <= 0) break;
        g_conc_done_reqs++;
    }

done:
    anet_socket_close(gen_var(cli));
    free(gen_var(cli));
    gen_var(cli) = NULL;
    g_conc_pending--;
    gen_return(NULL);
    gen_end(NULL);
}

task_t* task(conc_bench_task) {
    gen_dec_vars(
        int      i;
        uint64_t t0;
        task_t  *ct;
    );
    gen_begin(ctx);

    g_conc_pending = CONC_CONNS;
    g_conc_done_reqs = 0;
    gen_var(t0) = now_us();

    for (gen_var(i) = 0; gen_var(i) < CONC_CONNS; gen_var(i)++) {
        gen_var(ct) = conc_conn_task();
        if (!gen_var(ct)) { g_conc_pending--; continue; }
        task_run(gen_var(ct));
    }

    while (g_conc_pending > 0) {
        gen_yield(async_sleep(2));
    }

    {
        uint64_t elapsed_us = now_us() - gen_var(t0);
        if (elapsed_us == 0) elapsed_us = 1;
        double rps = (double)g_conc_done_reqs * 1000000.0 / (double)elapsed_us;
        printf("[conc] conns=%d x %d = %d reqs  elapsed=%llums  throughput=%.0f req/s\n",
               CONC_CONNS, CONC_PER, g_conc_done_reqs, (unsigned long long)(elapsed_us/1000), rps);
    }

    gen_return(0);   /* 子任务: 由 master 收尾 */
    gen_end(NULL);
}

/* master: 依次跑 seq 与 conc 两个子场景, 全程一个 accept 循环。 */
task_t* task(bench_master_task) {
    gen_dec_vars(
        task_t *accept_task;
        task_t *phase;
    );
    gen_begin(ctx);

    gen_var(accept_task) = anet_http_server_run(g_server);
    task_run(gen_var(accept_task));

    gen_var(phase) = seq_bench_task();
    gen_yield_from_task(gen_var(phase));

    gen_var(phase) = conc_bench_task();
    gen_yield_from_task(gen_var(phase));

    anet_http_server_stop(g_server);
    gen_yield(async_sleep(10));

    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int main(int argc, char **argv) {
    if (argc > 1) SEQ_N = atoi(argv[1]);
    if (argc > 2) CONC_CONNS = atoi(argv[2]);
    if (argc > 3) CONC_PER = atoi(argv[3]);

    if (anet_init() != ANET_OK) { printf("init failed\n"); return 1; }
    g_server = anet_http_server_create(0, bench_handler, NULL);
    if (!g_server) { printf("server create failed\n"); return 1; }
    g_port = anet_http_server_port(g_server);
    printf("bench server on 127.0.0.1:%u\n", g_port);

    /* 单个 accept 循环, master 依次驱动 seq 与 conc 两阶段。 */
    loop_run(bench_master_task());

    anet_http_server_destroy(g_server);
    anet_cleanup();
    return 0;
}
