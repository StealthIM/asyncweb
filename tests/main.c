#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_sync_http();
int test_async_http();
int test_sync_ws();
int test_async_ws();

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

    printf("Unknown test: %s\n", argv[1]);
    printf("Available tests: sync_http, async_http, sync_ws, async_ws\n");
    return 1;
}
