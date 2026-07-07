#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_sync_http();
int test_async_http();
int test_sync_ws();
int test_async_ws();
int test_server();
int test_server6();
int test_http_server();
int test_https_server();
int test_keepalive();
int test_ws_server();
int test_wss_server();
int test_server_adversarial();
int test_server_concurrent();

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        printf("Usage: %s <testname>\n", argv[0]);
        printf("Available tests: sync_http, async_http, sync_ws, async_ws\n");
        return 1;
    }
    if (strcmp(argv[1], "sync_http") == 0) {
        return test_sync_http();
    }
    if (strcmp(argv[1], "async_http") == 0) {
        return test_async_http();
    }
    if (strcmp(argv[1], "sync_ws") == 0) {
        return test_sync_ws();
    }
    if (strcmp(argv[1], "async_ws") == 0) {
        return test_async_ws();
    }
    if (strcmp(argv[1], "server") == 0) {
        return test_server();
    }
    if (strcmp(argv[1], "server6") == 0) {
        return test_server6();
    }
    if (strcmp(argv[1], "http_server") == 0) {
        return test_http_server();
    }
    if (strcmp(argv[1], "https_server") == 0) {
        return test_https_server();
    }
    if (strcmp(argv[1], "keepalive") == 0) {
        return test_keepalive();
    }
    if (strcmp(argv[1], "ws_server") == 0) {
        return test_ws_server();
    }
    if (strcmp(argv[1], "wss_server") == 0) {
        return test_wss_server();
    }
    if (strcmp(argv[1], "server_adversarial") == 0) {
        return test_server_adversarial();
    }
    if (strcmp(argv[1], "server_concurrent") == 0) {
        return test_server_concurrent();
    }

    printf("Unknown test: %s\n", argv[1]);
    printf("Available tests: sync_http, async_http, sync_ws, async_ws, server, server6, http_server, https_server, keepalive, ws_server, wss_server\n");
    return 1;
}
