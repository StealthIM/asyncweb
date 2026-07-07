# asyncweb

asyncweb 是一个用 C11 编写的异步 HTTP / HTTPS / WebSocket 库,客户端与服务端全覆盖。
它构建在协程库 [libcoro](https://github.com/StealthIM/libcoro) 之上:高层 API 既有
**同步**风格(自己驱动事件循环,直接返回结果),也有**异步**风格(在协程里 await)。

## 特性

- **HTTP/1.1 客户端**:同步 + 异步,GET / POST / 任意方法
- **HTTP/1.1 服务端**:handler 回调 + keep-alive,支持明文与 HTTPS
- **WebSocket**:客户端 + 服务端,明文 ws 与 wss(over TLS)
- **双 TLS 后端**:OpenSSL 或 wolfSSL(编译期选)
- **多平台**:POSIX / Windows / lwIP(含 FreeRTOS + 裸机 NO_SYS)
- **内存证书**:`*_mem` 变体支持内嵌 DER/PEM 证书,适配无文件系统的嵌入式目标

## 依赖

- CMake ≥ 3.16、C11 编译器
- **libcoro**:优先 `find_package`(系统已装),否则自动 FetchContent 源码
- **TLS 后端**:OpenSSL(`find_package`)或 wolfSSL(`find_package` 优先,否则 FetchContent)

## 后端选择

构建时通过 cache 变量选后端:

| 变量 | 取值 | 说明 |
|------|------|------|
| `ASYNCWEB_OS_BACKEND`  | `posix` / `win` / `lwip` | OS socket 层。`lwip` 要求 libcoro 也以 `LIBCORO_OS_BACKEND=lwip` 构建 |
| `ASYNCWEB_SSL_BACKEND` | `openssl` / `wolfssl`    | TLS 后端 |
| `ASYNCWEB_WS`          | `on` / `off`             | 是否启用 WebSocket |
| `ASYNCWEB_STANDALONE`  | `ON` / `OFF`             | 是否构建测试(默认 `OFF`) |

## 构建

```bash
# POSIX + OpenSSL + WebSocket
cmake -B build -DASYNCWEB_OS_BACKEND=posix -DASYNCWEB_SSL_BACKEND=openssl -DASYNCWEB_WS=on
cmake --build build
```

```bash
# wolfSSL 后端
cmake -B build -DASYNCWEB_OS_BACKEND=posix -DASYNCWEB_SSL_BACKEND=wolfssl -DASYNCWEB_WS=on
cmake --build build
```

### 安装 / find_package / pkg-config

```bash
cmake -B build -DASYNCWEB_OS_BACKEND=posix -DASYNCWEB_SSL_BACKEND=openssl -DASYNCWEB_WS=on \
      -DCMAKE_INSTALL_PREFIX=/your/prefix
cmake --build build --target install
```

下游 CMake:

```cmake
find_package(asyncweb REQUIRED)   # 透传拉入 libcoro + SSL 后端
target_link_libraries(your_app PRIVATE asyncweb::asyncweb)
```

> 注意:若 wolfSSL 是通过 FetchContent 源码内建(系统未装),则该内建静态库不可导出,
> asyncweb 会**跳过 install** 并告警。要安装 asyncweb 请用系统 wolfSSL,或用 openssl 后端。

## 用法

所有 API 用前须调 `anet_init()`,结束时 `anet_cleanup()`。注意状态码取值与 C 惯例相反:

```c
typedef enum { ANET_OK = 1, ANET_ERR = 0 } anet_status_t;

anet_status_t anet_init();
void          anet_cleanup();
```

### 同步 HTTP 客户端

同步调用自己驱动事件循环、阻塞到完成,调用方无需管 loop。见
[`examples/http_get.c`](examples/http_get.c)。

```c
#include <asyncweb/asyncweb.h>

anet_init();

anet_sync_http_response_t resp;
if (anet_sync_http_get("http://postman-echo.com/get", &resp) == ANET_OK) {
    printf("Status: %d %s\n", resp.status_code, resp.status_text);
    printf("Body:\n%s\n", resp.body);
    anet_sync_http_response_free(&resp);
}

anet_cleanup();
```

### 异步 HTTP 客户端

在协程里发请求、`gen_yield_from_task` 等它完成,再从 `task->future` 读结果:

```c
#include <libcoro/libcoro.h>
#include <asyncweb/asyncweb.h>

task_t* task(fetch) {
    gen_dec_vars(
        anet_async_http_response_t response;
        task_t *req;
    );
    gen_begin(ctx);

    gen_var(req) = anet_async_http_get("http://postman-echo.com/get", &gen_var(response));
    gen_yield_from_task(gen_var(req));

    if (future_result(gen_var(req)->future) != (void*)ANET_ERR) {
        printf("Status: %d\n", gen_var(response).status_code);
        printf("Body:\n%s\n", gen_var(response).body);
        anet_http_response_free(&gen_var(response));
    }
    loop_stop();
    gen_end(NULL);
}

int main(void) {
    anet_init();
    loop_run(fetch());
    anet_cleanup();
}
```

### HTTP 服务端

handler 填充预置默认值的 `resp`;accept 循环是一个 task,用 `loop_run` 驱动。见
[`examples/http_server.c`](examples/http_server.c)。

```c
static void handler(const anet_http_server_request_t *req,
                    anet_http_server_response_t *resp, void *ud) {
    static char body[512];
    snprintf(body, sizeof(body), "%s %s", req->method, req->path);
    resp->status_code = 200;
    resp->body = body;              /* body_len=0 => strlen(body) */
}

anet_init();
anet_http_server_t *srv = anet_http_server_create(8080, handler, NULL); /* port 0 = 临时端口 */
loop_run(anet_http_server_run(srv));   /* 服务到 anet_http_server_stop */
anet_http_server_destroy(srv);
anet_cleanup();
```

> 服务端默认绑 `127.0.0.1` 且**无鉴权**。要暴露到网络请自行加访问控制。

HTTPS 在 `create` 与 `run` 之间加 TLS:

```c
anet_http_server_use_tls(srv, "cert.pem", "key.pem");        /* PEM 文件 */
anet_http_server_use_tls_mem(srv, cert, cert_len, key, key_len, is_der); /* 内存证书 */
```

## API 概览

### 通用 (`asyncweb/common.h`)

```c
anet_status_t anet_init();
void          anet_cleanup();
```

### HTTP 客户端 (`asyncweb/http.h`)

```c
/* 同步: 阻塞到完成 */
anet_status_t anet_sync_http_get(const char *url, anet_sync_http_response_t *resp);
anet_status_t anet_sync_http_post(const char *url, const char *content_type,
                                  const char *body, anet_sync_http_response_t *resp);
anet_status_t anet_sync_http_request(const char *method, const char *host, uint16_t port,
                                     int use_tls, const char *path, const char **headers,
                                     const char *body, anet_sync_http_response_t *resp);
void anet_sync_http_response_free(anet_sync_http_response_t *resp);

/* 异步: 返回 task, 在协程里 await */
task_t* anet_async_http_get(const char *url, anet_async_http_response_t *resp);
task_t* anet_async_http_post(const char *url, const char *content_type,
                             const char *body, anet_async_http_response_t *resp);
task_t* anet_async_http_request(anet_async_http_request_t *req);
void    anet_http_response_free(anet_async_http_response_t *resp);
```

响应结构(同步/异步同形):`status_code` / `status_text` / `headers` / `headers_len` /
`body` / `body_len`。

### HTTP 服务端 (`asyncweb/http_server.h`)

```c
anet_http_server_t* anet_http_server_create(uint16_t port, anet_http_handler_t handler, void *ud);
int      anet_http_server_use_tls(anet_http_server_t *s, const char *cert_path, const char *key_path);
int      anet_http_server_use_tls_mem(anet_http_server_t *s, const unsigned char *cert, int cert_len,
                                       const unsigned char *key, int key_len, int is_der);
uint16_t anet_http_server_port(anet_http_server_t *s);
task_t*  anet_http_server_run(anet_http_server_t *s);
void     anet_http_server_stop(anet_http_server_t *s);
void     anet_http_server_destroy(anet_http_server_t *s);
```

### WebSocket (`asyncweb/ws.h`)

```c
/* 客户端 */
task_t*       anet_async_ws_connect(const char *url, anet_async_ws_t **ws);
task_t*       anet_async_ws_connect_mem(const char *url, const unsigned char *ca, int ca_len,
                                        int is_der, anet_async_ws_t **ws);   /* wss + 内存 CA */
anet_status_t anet_sync_ws_connect(const char *url, anet_sync_ws_t **ws);

/* 服务端: 升级一个已 accept 的 socket */
task_t* anet_async_ws_accept(anet_socket_t *sock, anet_async_ws_t **out);
task_t* anet_async_ws_accept_tls(anet_socket_t *sock, const char *cert_path,
                                 const char *key_path, anet_async_ws_t **out);
task_t* anet_async_ws_accept_tls_mem(anet_socket_t *sock, const unsigned char *cert, int cert_len,
                                     const unsigned char *key, int key_len, int is_der,
                                     anet_async_ws_t **out);

/* 收发: anet_async_ws_send/recv/close/get_state/destroy (+ 对应 anet_sync_ 变体) */
```

## 目录

- `include/asyncweb/` — 公开头(安装)
- `include/asyncweb_internal/` — 内部头(不安装)
- `src/` — 实现(`sock/` socket+stream 层,`tls/` TLS 后端)
- `examples/` — 最小示例
- `tests/` — 端到端测试

## 许可证

MIT
