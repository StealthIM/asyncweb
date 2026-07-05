#pragma once

/*
 * 测试用 TLS 证书辅助。
 *
 * 证书是预生成的固定资产 (tests/certs/,SAN IP:127.0.0.1,100 年有效期),
 * 不在运行时生成——这样测试与具体 TLS 后端 (OpenSSL / wolfSSL) 解耦,
 * 换后端不必改测试。
 *
 * copy_test_certs() 把 cert.pem/key.pem/cacert.pem 从源目录拷到当前工作目录,
 * 供服务端加载 (cert.pem/key.pem) 和客户端信任 (./cacert.pem) 使用。
 * 测试通常先 chdir 进临时子目录再调用它,避免污染仓库工作树。
 */

#include <stdio.h>
#include <stdlib.h>

/* CERTS_SRC_DIR 由 CMake 以编译宏形式注入 (指向 tests/certs 的绝对路径)。
   未定义时退回相对路径,便于手动运行。 */
#ifndef CERTS_SRC_DIR
#  define CERTS_SRC_DIR "tests/certs"
#endif

static int copy_one_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }
    char buf[4096];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { rc = -1; break; }
    }
    fclose(in);
    fclose(out);
    return rc;
}

/* 把预生成证书拷到当前工作目录。返回 0 成功。 */
static int copy_test_certs(void) {
    const char *names[] = { "cert.pem", "key.pem", "cacert.pem" };
    for (int i = 0; i < 3; i++) {
        char src[1024];
        snprintf(src, sizeof(src), "%s/%s", CERTS_SRC_DIR, names[i]);
        if (copy_one_file(src, names[i]) != 0) return -1;
    }
    return 0;
}
