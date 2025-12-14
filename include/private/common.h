#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ANET_OK = 1,
    ANET_ERR = 0,
} anet_status_t;

anet_status_t anet_init();
void anet_cleanup();

#ifdef __cplusplus
}
#endif
