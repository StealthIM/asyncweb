#include "common.h"
#include "../include/private/sock/pal_socket.h"


anet_status_t anet_init() {
    anet_palsock_init();
    return ANET_OK;
}

void anet_cleanup() {
    anet_palsock_cleanup();
}