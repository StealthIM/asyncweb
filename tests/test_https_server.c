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
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "libcoro.h"
#include "asyncweb.h"

/*
 * HTTPS 服务端端到端测试:
 *   - 运行时生成自签名证书 (SAN IP:127.0.0.1),不落外部依赖
 *   - anet_http_server 启用 TLS 后监听 loopback
 *   - 用真实的异步 HTTPS 客户端 (完整校验:cert 链 + hostname) 请求
 *   - 全程在临时子目录里跑,自签名证书即作 ./cacert.pem,不动真实 CA 包
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

/* 生成自签名证书 + 私钥,写入 cert.pem/key.pem,并把证书复制到 cacert.pem
   (供客户端信任)。返回 0 成功。*/
static int generate_self_signed(void) {
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (!pkey) return -1;

    X509 *x = X509_new();
    if (!x) { EVP_PKEY_free(pkey); return -1; }

    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
    X509_set_pubkey(x, pkey);

    /* 不声明裸 X509_NAME 变量:Windows 的 wincrypt.h 把 X509_NAME 定义成宏,
       会污染 OpenSSL 的同名类型。内联返回值即可绕开。 */
    X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC,
                               (const unsigned char*)"127.0.0.1", -1, -1, 0);
    X509_set_issuer_name(x, X509_get_subject_name(x));   /* self-signed */

    /* SAN IP:127.0.0.1 —— 客户端按 IP 做 hostname 校验时需要 */
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
    /* 在临时子目录里跑:自签名证书即 ./cacert.pem,不污染真实 CA 包 */
    make_dir("tls_test_tmp");
    if (change_dir("tls_test_tmp") != 0) { printf("chdir failed\n"); return 1; }

    if (generate_self_signed() != 0) { printf("cert gen failed\n"); return 1; }

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
