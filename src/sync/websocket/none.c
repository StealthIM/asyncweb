#include "sync/websocket.h"
#include <stdlib.h>

struct anet_ws_t { int dummy; };

anet_ws_t* anet_ws_connect(const char* url) {
    (void)url;
    return NULL; // 不支持
}

anet_ws_status_t anet_ws_send(anet_ws_t* ws, const void* data, int len, int is_text) {
    (void)ws; (void)data; (void)len; (void)is_text;
    return ANET_WS_ERR;
}

int anet_ws_recv(anet_ws_t* ws, void* buffer, int maxlen, int* is_text) {
    (void)ws; (void)buffer; (void)maxlen; (void)is_text;
    return ANET_WS_ERR;
}

void anet_ws_close(anet_ws_t* ws) {
    (void)ws;
}
