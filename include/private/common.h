#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ANET_OK = 1,
    ANET_ERR = 0,
} anet_status_t;

anet_status_t anet_init();
void anet_cleanup();

/* ============================================================
 * 协程 / future 结果编解码
 *
 * libcoro 的 future 用泛型 void* 承载结果(类型写死在框架结构体里,
 * 而用户结果类型不定)。asyncweb 在其上约定两类整数语义,用下列 helper
 * 显式编解码,替代满屏裸 (void*)(intptr_t) 强转,并让每处结果到底用的是
 * 哪套约定(以及 0 的含义)一目了然:
 *
 *   - 状态码:   anet_res_status(ANET_OK|ANET_ERR) / anet_status_of(r)
 *               —— 0(ANET_ERR)=失败, 1(ANET_OK)=成功
 *   - IO/返回码: anet_res_code(n) / anet_code_of(r)
 *               —— 有符号:-1(或 <0)=错误, >=0 = 字节数/成功(0 可能是成功或 EOF)
 *   - 指针结果: 直接用真指针,失败为 NULL,无需 helper
 * ============================================================ */

static inline void* anet_res_status(anet_status_t s) { return (void*)(intptr_t)s; }
static inline anet_status_t anet_status_of(void *r) { return (anet_status_t)(intptr_t)r; }

static inline void* anet_res_code(intptr_t n) { return (void*)n; }
static inline intptr_t anet_code_of(void *r) { return (intptr_t)r; }

#ifdef __cplusplus
}
#endif
