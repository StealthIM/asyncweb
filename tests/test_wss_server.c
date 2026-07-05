#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "libcoro.h"
#include "asyncweb.h"

/*
 * WSS (WebSocket over TLS) 服务端端到端测试:
 *   - 运行时生成自签名证书 (SAN IP:127.0.0.1) 作 ./cacert.pem,不依赖外部 CA
 *   - 服务端:accept 一条连接 → anet_async_ws_accept_tls 先 TLS 握手再 WS 升级
 *     → recv 一条消息 → echo → 关闭
 *   - 客户端:wss://127.0.0.1:port 连接 (完整校验 cert 链 + hostname) → send
 *     → recv echo → 校验
 * 全程在临时子目录里跑。
 */

#define WSS_TEST_MSG "hello secure websocket"

static anet_palsock_t    g_listen_sock;
static async_listener_t *g_listener;
static uint16_t          g_port;

/* 与 test_https_server 同款:生成自签名证书 (cert.pem/key.pem/cacert.pem)。*/
static int generate_self_signed(void) {
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (!pkey) return -1;
    X509 *x = X509_new();
    if (!x) { EVP_PKEY_free(pkey); return -1; }
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC,
                               (const unsigned char*)"127.0.0.1", -1, -1, 0);
    X509_set_issuer_name(x, X509_get_subject_name(x));
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, x, x, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &v3ctx,
                                              NID_subject_alt_name, "IP:127.0.0.1");
    if (ext) { X509_add_ext(x, ext, -1); X509_EXTENSION_free(ext); }
    if (X509_sign(x, pkey, EVP_sha256()) == 0) {
        X509_free(x); EVP_PKEY_free(pkey); return -1;
    }
    int rc = -1;
    FILE *fk = fopen("key.pem", "wb");
    FILE *fc = fopen("cert.pem", "wb");
    FILE *fca = fopen("cacert.pem", "wb");
    if (fk && fc && fca &&
        PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL) == 1 &&
        PEM_write_X509(fc, x) == 1 &&
        PEM_write_X509(fca, x) == 1) {
        rc = 0;
    }
    if (fk) fclose(fk);
    if (fc) fclose(fc);
    if (fca) fclose(fca);
    X509_free(x);
    EVP_PKEY_free(pkey);
    return rc;
}

/* --- 服务端协程 --- */
task_t* task(wss_server_task) {
    gen_dec_vars(
        future_t        *accept_fut;
        async_socket_t  *conn;
        anet_async_ws_t *ws;
        anet_ws_message_t msg;
        task_t          *task;
    );
    gen_begin(ctx);

    gen_var(accept_fut) = async_socket_accept(g_listener);
    gen_yield(gen_var(accept_fut));
    if (future_is_rejected(gen_var(accept_fut))) { printf("server accept failed\n"); exit(1); }
    gen_var(conn) = (async_socket_t*)future_result(gen_var(accept_fut));

    /* TLS 握手 + WS 升级 */
    gen_var(task) = anet_async_ws_accept_tls(gen_var(conn), "cert.pem", "key.pem", &gen_var(ws));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server wss handshake failed\n"); exit(1);
    }
    printf("server: wss handshake done\n");

    gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server recv failed\n"); exit(1);
    }
    printf("server received: %s\n", gen_var(msg).data);

    gen_var(task) = anet_async_ws_send(gen_var(ws), gen_var(msg).type,
                                       gen_var(msg).data, gen_var(msg).len);
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("server echo failed\n"); exit(1);
    }
    anet_ws_message_free(&gen_var(msg));

    gen_var(task) = anet_async_ws_close(gen_var(ws));
    gen_yield_from_task(gen_var(task));
    anet_async_ws_destroy(gen_var(ws));

    printf("server: done\n");
    gen_return(0);
    gen_end(NULL);
}

/* --- 客户端协程 --- */
task_t* task(wss_client_task) {
    gen_dec_vars(
        anet_async_ws_t *ws;
        anet_ws_message_t msg;
        task_t          *task;
        char             url[128];
    );
    gen_begin(ctx);

    snprintf(gen_var(url), sizeof(gen_var(url)), "wss://127.0.0.1:%u/", g_port);
    gen_var(task) = anet_async_ws_connect(gen_var(url), &gen_var(ws));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) == NULL) { printf("client connect failed\n"); exit(1); }
    printf("client: connected\n");

    gen_var(task) = anet_async_ws_send(gen_var(ws), ANET_WS_TEXT, WSS_TEST_MSG, strlen(WSS_TEST_MSG));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("client send failed\n"); exit(1);
    }

    gen_var(task) = anet_async_ws_recv(gen_var(ws), &gen_var(msg));
    gen_yield_from_task(gen_var(task));
    if (future_result(gen_var(task)->future) != (void*)(intptr_t)ANET_OK) {
        printf("client recv failed\n"); exit(1);
    }
    printf("client received echo: %s\n", gen_var(msg).data);
    if (strcmp(gen_var(msg).data, WSS_TEST_MSG) != 0) {
        printf("echo mismatch: '%s'\n", gen_var(msg).data); exit(1);
    }
    anet_ws_message_free(&gen_var(msg));

    gen_var(task) = anet_async_ws_close(gen_var(ws));
    gen_yield_from_task(gen_var(task));
    anet_async_ws_destroy(gen_var(ws));

    printf("WSS server test passed\n");
    loop_stop();
    gen_return(0);
    gen_end(NULL);
}

int test_wss_server() {
    /* 在临时子目录里跑:自签名证书即 ./cacert.pem,不污染真实 CA 包 */
    make_dir("wss_test_tmp");
    if (change_dir("wss_test_tmp") != 0) { printf("chdir failed\n"); return 1; }
    if (generate_self_signed() != 0) { printf("cert gen failed\n"); return 1; }

    if (anet_init() != ANET_OK) { printf("Network init failed\n"); return 1; }

    g_listen_sock = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(g_listen_sock)) { printf("listen create failed\n"); return 1; }
    anet_palsock_set_reuseaddr(g_listen_sock, 1);
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = 0;
        if (anet_palsock_bind(g_listen_sock, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
            printf("bind failed\n"); return 1;
        }
        if (anet_palsock_listen(g_listen_sock, 4) != 0) { printf("listen failed\n"); return 1; }
        struct sockaddr_in bound; socklen_t bl = sizeof(bound);
        getsockname(g_listen_sock, (struct sockaddr*)&bound, &bl);
        g_port = ntohs(bound.sin_port);
    }
    g_listener = async_listener_create(g_listen_sock);
    printf("wss server listening on 127.0.0.1:%u\n", g_port);

    task_t *st = wss_server_task();
    task_run(st);
    task_t *ct = wss_client_task();
    loop_run(ct);

    async_listener_close(g_listener);
    free(g_listener);
    anet_cleanup();
    return 0;
}
