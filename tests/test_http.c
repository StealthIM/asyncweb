#include <stdio.h>
#include "asyncweb.h"

int test_http() {
    printf("Testing http");

    if (anet_init() != ANET_OK) {
        printf("Network init failed");
        return -1;
    }
    printf("Network inited");

    char buffer[8192];

    // 例子: GET
    const char* headers1[] = { "User-Agent: asyncweb/0.1", "Accept: */*", NULL };
    if (anet_http_request("GET", "postman-echo.com", 443, "/get?foo1=bar1&foo2=bar2", headers1, NULL, buffer, sizeof(buffer)) == ANET_OK) {
        printf("GET Response:\n%s\n", buffer);
    } else {
        return -1;
    }

    // 例子: POST JSON
    const char* headers2[] = { "User-Agent: asyncweb/0.1", "Content-Type: application/json", NULL };
    const char* body = "{ \"msg\": \"hello\" }";
    if (anet_http_request("POST", "postman-echo.com", 443, "/post", headers2, body, buffer, sizeof(buffer)) == ANET_OK) {
        printf("POST Response:\n%s\n", buffer);
    } else {
        return -1;
    }

    anet_cleanup();
    return 0;
}