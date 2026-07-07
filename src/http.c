#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <asyncweb/http.h>

#include <openssl/ssl.h>

#include <asyncweb_internal/tls.h>
#include <asyncweb/palsock.h>
#include <libcoro/libcoro.h>

#define HTTP_BUFFER_SIZE 8192
#define HTTP_MAX_HEADERS 64
#define HTTP_MAX_URL_LENGTH 2048

/* ============================================================
 * 内部辅助函数
 * ============================================================ */

typedef struct {
    future_t *fut;
    void     *data;
} done_future_helper_t;

// URL 解析结构
typedef struct {
    char scheme[16];
    char host[256];
    uint16_t port;
    char path[1024];
} parsed_url_t;

/* ============================================================
 * 共用辅助函数
 * ============================================================ */

// 解析 URL
static int parse_url(const char *url, parsed_url_t *parsed) {
    if (!url || !parsed) return -1;

    // 初始化
    memset(parsed, 0, sizeof(*parsed));
    strcpy(parsed->scheme, "https");
    strcpy(parsed->path, "/");
    parsed->port = 443;

    char url_copy[HTTP_MAX_URL_LENGTH];
    strncpy(url_copy, url, sizeof(url_copy) - 1);
    url_copy[sizeof(url_copy) - 1] = '\0';

    // 解析协议
    char *scheme_end = strstr(url_copy, "://");
    if (scheme_end) {
        size_t scheme_len = scheme_end - url_copy;
        if (scheme_len >= sizeof(parsed->scheme)) return -1;
        strncpy(parsed->scheme, url_copy, scheme_len);
        parsed->scheme[scheme_len] = '\0';
        scheme_end += 3;
    } else {
        scheme_end = url_copy;
    }

    // 解析主机和路径
    char *host_start = scheme_end;
    char *path_start = strchr(host_start, '/');
    if (path_start) {
        size_t path_len = strlen(path_start);
        if (path_len >= sizeof(parsed->path)) return -1;
        strcpy(parsed->path, path_start);
        *path_start = '\0';  // 暂时截断，便于解析主机
    }

    // 解析端口
    char *port_start = strchr(host_start, ':');
    if (port_start) {
        parsed->port = (uint16_t)atoi(port_start + 1);
        *port_start = '\0';  // 截断，便于解析主机
    } else {
        // 根据协议设置默认端口
        if (strcmp(parsed->scheme, "http") == 0) {
            parsed->port = 80;
        } else if (strcmp(parsed->scheme, "https") == 0) {
            parsed->port = 443;
        }
    }

    // 复制主机名
    if (strlen(host_start) >= sizeof(parsed->host)) return -1;
    strcpy(parsed->host, host_start);

    return 0;
}

// 创建请求字符串
static char* create_request_string(const char *method,
                                  const char *host,
                                  uint16_t port,
                                  const char *path,
                                  const char **headers,
                                  const char *body) {
    // 计算所需缓冲区大小
    size_t size = strlen(method) + strlen(path) + strlen("HTTP/1.1\r\n") + 256;
    
    // Host 头部
    size += strlen("Host: ") + strlen(host) + 16;
    
    // 其他头部
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            size += strlen(headers[i]) + 2;  // +2 for \r\n
        }
    }
    
    // Content-Length
    if (body) {
        size += strlen("Content-Length: ") + 32;
    }
    
    // 空行和body
    size += 3;  // \r\n\r\n
    if (body) {
        size += strlen(body);
    }
    
    char *request = malloc(size + 1);
    if (!request) return NULL;
    
    // 构建请求
    sprintf(request, "%s %s HTTP/1.1\r\n", method, path);
    
    // Host 头部：标准端口（80/443）省略端口号，其余带端口
    if (port == 80 || port == 443) {
        sprintf(request + strlen(request), "Host: %s\r\n", host);
    } else {
        sprintf(request + strlen(request), "Host: %s:%d\r\n", host, port);
    }
    
    // 其他头部
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            strcat(request, headers[i]);
            strcat(request, "\r\n");
        }
    }
    
    // Content-Length
    if (body) {
        sprintf(request + strlen(request), "Content-Length: %zu\r\n", strlen(body));
    }
    
    // 空行
    strcat(request, "\r\n");
    
    // Body
    if (body) {
        strcat(request, body);
    }
    
    return request;
}

// 解析响应
static int parse_response(const char *response_data, size_t response_len, void *response_ptr, int is_async) {
    if (!response_data || !response_ptr) return -1;
    
    // 查找状态行结束
    const char *status_line_end = strstr(response_data, "\r\n");
    if (!status_line_end) return -1;
    
    // 解析状态行
    char status_line[256];
    size_t status_line_len = status_line_end - response_data;
    if (status_line_len >= sizeof(status_line)) return -1;
    
    strncpy(status_line, response_data, status_line_len);
    status_line[status_line_len] = '\0';
    
    // 解析状态码
    char *status_code_start = strchr(status_line, ' ');
    if (!status_code_start) return -1;
    status_code_start++;
    
    char *status_text_start = strchr(status_code_start, ' ');
    if (!status_text_start) return -1;
    *status_text_start = '\0';
    status_text_start++;
    
    if (is_async) {
        anet_async_http_response_t *response = (anet_async_http_response_t*)response_ptr;
        response->status_code = atoi(status_code_start);
        response->status_text = strdup(status_text_start);
        
        // 查找头部结束
        const char *headers_end = strstr(status_line_end + 2, "\r\n\r\n");
        if (!headers_end) return -1;
        
        // 复制头部
        size_t headers_len = headers_end - (status_line_end + 2);
        response->headers_len = headers_len;
        response->headers = malloc(headers_len + 1);
        if (!response->headers) return -1;
        
        memcpy(response->headers, status_line_end + 2, headers_len);
        response->headers[headers_len] = '\0';
        
        // 复制body
        const char *body_start = headers_end + 4;
        size_t body_len = response_len - (body_start - response_data);
        response->body_len = body_len;
        
        if (body_len > 0) {
            response->body = malloc(body_len + 1);
            if (!response->body) return -1;
            
            memcpy(response->body, body_start, body_len);
            response->body[body_len] = '\0';
        } else {
            response->body = NULL;
        }
    } else {
        anet_sync_http_response_t *response = (anet_sync_http_response_t*)response_ptr;
        response->status_code = atoi(status_code_start);
        response->status_text = strdup(status_text_start);
        
        // 查找头部结束
        const char *headers_end = strstr(status_line_end + 2, "\r\n\r\n");
        if (!headers_end) return -1;
        
        // 复制头部
        size_t headers_len = headers_end - (status_line_end + 2);
        response->headers_len = headers_len;
        response->headers = malloc(headers_len + 1);
        if (!response->headers) return -1;
        
        memcpy(response->headers, status_line_end + 2, headers_len);
        response->headers[headers_len] = '\0';
        
        // 复制body
        const char *body_start = headers_end + 4;
        size_t body_len = response_len - (body_start - response_data);
        response->body_len = body_len;
        
        if (body_len > 0) {
            response->body = malloc(body_len + 1);
            if (!response->body) return -1;
            
            memcpy(response->body, body_start, body_len);
            response->body[body_len] = '\0';
        } else {
            response->body = NULL;
        }
    }
    
    return 0;
}

/* ============================================================
 * 同步HTTP实现
 * ============================================================ */

// 发送 HTTP 请求
anet_status_t anet_sync_http_request(const char *method,
                     const char *host,
                     uint16_t port,
                     int use_tls,
                     const char *path,
                     const char **headers,
                     const char *body,
                     anet_sync_http_response_t *response) {
    if (!method || !host || !path || !response) return ANET_ERR;
    
    // 初始化响应结构
    memset(response, 0, sizeof(*response));
    
    // 初始化平台socket
    anet_palsock_init();
    
    // 解析地址 (先 resolve,再按返回的地址族建 socket,支持 v4/v6)
    struct sockaddr_storage addr;
    int addr_len;
    if (anet_palsock_resolve(host, AF_UNSPEC, &addr, &addr_len) != 0) {
        anet_palsock_cleanup();
        return ANET_ERR;
    }
    
    // 设置端口
    if (addr.ss_family == AF_INET) {
        ((struct sockaddr_in*)&addr)->sin_port = htons(port);
    } else if (addr.ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&addr)->sin6_port = htons(port);
    }
    
    // 按地址族创建 socket
    anet_palsock_t sock = anet_palsock_create(addr.ss_family, SOCK_STREAM, 0, 0);
    if (!anet_palsock_is_valid(sock)) {
        anet_palsock_cleanup();
        return ANET_ERR;
    }
    
    // 连接
    if (anet_palsock_connect(sock, (struct sockaddr*)&addr, addr_len) != 0) {
        anet_palsock_close(sock);
        anet_palsock_cleanup();
        return ANET_ERR;
    }
    
    // 创建stream
    sync_stream_t *stream = NULL;
    int is_ssl = use_tls;
    
    if (is_ssl) {
        // 创建SSL
        sync_ssl_t *ssl = sync_ssl_create(SYNC_SSL_CLIENT, host);
        if (!ssl) {
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return ANET_ERR;
        }
        
        sync_ssl_attach_socket(ssl, sock);
        
        // SSL握手
        if (sync_ssl_handshake(ssl) != 0) {
            sync_ssl_destroy(ssl);
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return ANET_ERR;
        }
        
        stream = sync_stream_from_ssl(ssl);
        if (!stream) {
            sync_ssl_destroy(ssl);
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return ANET_ERR;
        }
    } else {
        stream = sync_stream_from_socket(sock);
        if (!stream) {
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return ANET_ERR;
        }
    }
    
    // 创建请求
    char *request = create_request_string(method, host, port, path, headers, body);
    if (!request) {
        sync_stream_destroy(stream);
        anet_palsock_cleanup();
        return ANET_ERR;
    }
    
    // 发送请求
    if (sync_stream_write(stream, request, strlen(request)) != 0) {
        free(request);
        sync_stream_destroy(stream);
        anet_palsock_cleanup();
        return ANET_ERR;
    }
    free(request);
    
    // 读取响应
    char buffer[HTTP_BUFFER_SIZE];
    size_t total_read = 0;
    char *response_data = NULL;
    size_t response_capacity = 0;
    
    while (1) {
        int bytes_read = sync_stream_read(stream, sizeof(buffer), buffer);
        if (bytes_read <= 0) break;
        
        // 扩展响应缓冲区 (多留 1 字节给结尾 NUL, 使 strstr 不越界)
        if (total_read + bytes_read + 1 > response_capacity) {
            size_t new_capacity = response_capacity ? response_capacity * 2 : 4096;
            while (new_capacity < total_read + bytes_read + 1) {
                new_capacity *= 2;
            }

            char *new_data = realloc(response_data, new_capacity);
            if (!new_data) {
                free(response_data);
                sync_stream_destroy(stream);
                anet_palsock_cleanup();
                return ANET_ERR;
            }

            response_data = new_data;
            response_capacity = new_capacity;
        }

        // 复制数据并保持 NUL 结尾 (下面 strstr / parse_response 依赖它)
        memcpy(response_data + total_read, buffer, bytes_read);
        total_read += bytes_read;
        response_data[total_read] = '\0';

        // 完整性检查基于分隔符,不解析 Content-Length
        if (total_read > 4 && strstr(response_data, "\r\n\r\n")) {
            // 检查是否有Content-Length
            const char *headers_end = strstr(response_data, "\r\n\r\n");
            const char *content_length = strstr(response_data, "Content-Length:");
            if (content_length && content_length < headers_end) {
                int length = atoi(content_length + 15);
                size_t body_start = (headers_end + 4) - response_data;
                if (total_read >= body_start + length) {
                    break;
                }
            }
        }
    }
    
    // 解析响应
    int result = parse_response(response_data, total_read, response, 0);
    
    free(response_data);
    sync_stream_destroy(stream);
    anet_palsock_cleanup();
    
    return (result == 0) ? ANET_OK : ANET_ERR;
}

// 释放 HTTP 响应资源
void anet_sync_http_response_free(anet_sync_http_response_t *response) {
    if (!response) return;
    
    free(response->status_text);
    free(response->headers);
    free(response->body);
    memset(response, 0, sizeof(*response));
}

// 简化的 GET 请求
anet_status_t anet_sync_http_get(const char *url, anet_sync_http_response_t *response) {
    parsed_url_t parsed;
    if (parse_url(url, &parsed) != 0) return ANET_ERR;
    
    const char *headers[] = { "User-Agent: asyncweb/0.1", "Accept: */*", NULL };
    int use_tls = (strcmp(parsed.scheme, "https") == 0);
    return anet_sync_http_request("GET", parsed.host, parsed.port, use_tls, parsed.path, headers, NULL, response);
}

// 简化的 POST 请求
anet_status_t anet_sync_http_post(const char *url, const char *content_type, const char *body, anet_sync_http_response_t *response) {
    parsed_url_t parsed;
    if (parse_url(url, &parsed) != 0) return ANET_ERR;
    
    const char *headers[4] = { "User-Agent: asyncweb/0.1", NULL, NULL, NULL };
    char ct_header[256];

    if (content_type) {
        snprintf(ct_header, sizeof(ct_header), "Content-Type: %s", content_type);
        headers[1] = ct_header;
    }
    
    int use_tls = (strcmp(parsed.scheme, "https") == 0);
    return anet_sync_http_request("POST", parsed.host, parsed.port, use_tls, parsed.path, headers, body, response);
}

/* ============================================================
 * 异步HTTP实现
 * ============================================================ */

// 异步HTTP请求参数扩展
typedef struct {
    const char *method;
    const char *host;
    uint16_t port;
    int use_tls;
    const char *path;
    const char **headers;
    const char *body;
    anet_async_http_response_t *response;
    
    // 内部状态
    parsed_url_t parsed;
    anet_palsock_t sock;
    anet_socket_t *async_sock;
    async_ssl_t *async_ssl;
    anet_stream_t *stream;
    char *request;
    char *response_data;
    size_t response_capacity;
    size_t total_read;
} async_http_internal_t;

// 异步HTTP请求协程
task_t* task_arg(anet_async_http_request_) {
    gen_dec_vars(
        async_http_internal_t *req;
        future_t *fut;
        future_t *resolve_fut;
        task_t *task;
        struct sockaddr_storage addr;
        int addr_len;
        char buffer[HTTP_BUFFER_SIZE];
        int bytes_read;
    );
    gen_begin(ctx);

    {
        anet_async_http_request_t *in = (anet_async_http_request_t*)arg;
        
        // 创建内部请求结构
        gen_var(req) = calloc(1, sizeof(*gen_var(req)));
        if (!gen_var(req)) {
            gen_return(anet_res_status(ANET_ERR));
        }
        
        // 复制参数
        gen_var(req)->method = in->method;
        gen_var(req)->host = in->host;
        gen_var(req)->port = in->port;
        gen_var(req)->use_tls = in->use_tls;
        gen_var(req)->path = in->path;
        gen_var(req)->headers = in->headers;
        gen_var(req)->body = in->body;
        gen_var(req)->response = in->response;
        
        // 初始化响应结构
        memset(gen_var(req)->response, 0, sizeof(*gen_var(req)->response));

        gen_var(req)->sock = -1;
    }

    // 步骤1: 异步解析地址 (阻塞 getaddrinfo offload 到线程池)
    gen_var(resolve_fut) = anet_palsock_resolve_async(gen_var(req)->host, AF_UNSPEC);
    if (!gen_var(resolve_fut)) {
        gen_return(anet_res_status(ANET_ERR));
    }
    gen_yield(gen_var(resolve_fut));
    {
        anet_resolve_result_t *r = (anet_resolve_result_t*)future_result(gen_var(resolve_fut));
        if (!r || r->ok != 0) {
            free(r);
            gen_return(anet_res_status(ANET_ERR));
        }
        gen_var(addr) = r->addr;
        gen_var(addr_len) = r->addr_len;
        free(r);
    }

    // 设置端口
    if (gen_var(addr).ss_family == AF_INET) {
        ((struct sockaddr_in*)&gen_var(addr))->sin_port = htons(gen_var(req)->port);
    } else if (gen_var(addr).ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&gen_var(addr))->sin6_port = htons(gen_var(req)->port);
    }

    // 步骤2: 按地址族创建 socket
    gen_var(req)->sock = anet_palsock_create(gen_var(addr).ss_family, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(req)->sock)) {
        gen_return(anet_res_status(ANET_ERR));
    }

    // 创建异步socket
    gen_var(req)->async_sock = anet_socket_create(gen_var(req)->sock);
    if (!gen_var(req)->async_sock) {
        gen_return(anet_res_status(ANET_ERR));
    }

    // 步骤3: 连接
    gen_var(fut) = anet_socket_connect(gen_var(req)->async_sock, (struct sockaddr*)&gen_var(addr), gen_var(addr_len));
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) {
        gen_return(anet_res_status(ANET_ERR));
    }

    // 步骤4: 创建SSL（如果是HTTPS）
    int is_ssl = gen_var(req)->use_tls;

    if (is_ssl) {
        gen_var(req)->async_ssl = async_ssl_create(ASYNC_SSL_CLIENT, gen_var(req)->host);
        if (!gen_var(req)->async_ssl) {
            gen_return(anet_res_status(ANET_ERR));
        }

        async_ssl_attach_socket(gen_var(req)->async_ssl, gen_var(req)->async_sock);

        // 步骤5: SSL握手
        gen_var(task) = async_ssl_handshake(gen_var(req)->async_ssl);
        gen_yield_from_task(gen_var(task));

        if (anet_code_of(future_result(gen_var(task)->future)) != 0) {
            gen_return(anet_res_status(ANET_ERR));
        }

        gen_var(req)->stream = anet_stream_from_ssl(gen_var(req)->async_ssl);
        if (!gen_var(req)->stream) {
            gen_return(anet_res_status(ANET_ERR));
        }

    } else {
        gen_var(req)->stream = anet_stream_from_socket(gen_var(req)->async_sock);
        if (!gen_var(req)->stream) {
            gen_return(anet_res_status(ANET_ERR));
        }
    }

    // 步骤6: 创建请求
    gen_var(req)->request = create_request_string(
        gen_var(req)->method,
        gen_var(req)->host,
        gen_var(req)->port,
        gen_var(req)->path,
        gen_var(req)->headers,
        gen_var(req)->body
    );
    if (!gen_var(req)->request) {
        gen_return(anet_res_status(ANET_ERR));
    }

    // 步骤7: 发送请求
    gen_var(task) = anet_stream_write_all(gen_var(req)->stream, gen_var(req)->request, strlen(gen_var(req)->request));
    gen_yield_from_task(gen_var(task));

    if (anet_code_of(future_result(gen_var(task)->future)) != 0) {
        gen_return(anet_res_status(ANET_ERR));
    }

    free(gen_var(req)->request);
    gen_var(req)->request = NULL;

    // 步骤8: 读取响应
    while (1) {
        gen_var(task) = anet_stream_read(gen_var(req)->stream, sizeof(gen_var(buffer)), gen_var(buffer));
        gen_yield_from_task(gen_var(task));
        
        gen_var(bytes_read) = (int)anet_code_of(future_result(gen_var(task)->future));
        if (gen_var(bytes_read) <= 0) {
            // 读取完成，解析响应
            if (gen_var(req)->total_read > 0) {
                int result = parse_response(gen_var(req)->response_data, gen_var(req)->total_read, gen_var(req)->response, 1);
                gen_return(anet_res_status(result == 0 ? ANET_OK : ANET_ERR));
            }
            gen_return(anet_res_status(ANET_ERR));
        }

        // 扩展响应缓冲区 (多留 1 字节给结尾 NUL, 使 strstr 不越界)
        if (gen_var(req)->total_read + gen_var(bytes_read) + 1 > gen_var(req)->response_capacity) {
            size_t new_capacity = gen_var(req)->response_capacity ? gen_var(req)->response_capacity * 2 : 4096;
            while (new_capacity < gen_var(req)->total_read + gen_var(bytes_read) + 1) {
                new_capacity *= 2;
            }

            char *new_data = realloc(gen_var(req)->response_data, new_capacity);
            if (!new_data) {
                gen_return(anet_res_status(ANET_ERR));
            }

            gen_var(req)->response_data = new_data;
            gen_var(req)->response_capacity = new_capacity;
        }

        // 复制数据并保持 NUL 结尾 (下面 strstr / parse_response 依赖它)
        memcpy(gen_var(req)->response_data + gen_var(req)->total_read, gen_var(buffer), gen_var(bytes_read));
        gen_var(req)->total_read += gen_var(bytes_read);
        gen_var(req)->response_data[gen_var(req)->total_read] = '\0';

        // 检查是否读取完整
        if (gen_var(req)->total_read > 4 && strstr(gen_var(req)->response_data, "\r\n\r\n")) {
            const char *headers_end = strstr(gen_var(req)->response_data, "\r\n\r\n");
            const char *content_length = strstr(gen_var(req)->response_data, "Content-Length:");
            if (content_length && content_length < headers_end) {
                int length = atoi(content_length + 15);
                size_t body_start = (headers_end + 4) - gen_var(req)->response_data;
                if (gen_var(req)->total_read >= body_start + length) {
                    // 读取完成，解析响应
                    int result = parse_response(gen_var(req)->response_data, gen_var(req)->total_read, gen_var(req)->response, 1);
                    gen_return(anet_res_status(result == 0 ? ANET_OK : ANET_ERR));
                }
            }
        }
    }
        // 继续读取
        // 不改变step，继续循环

    gen_cleanup();
    // 统一 teardown：无论哪个 gen_return 退出，gen_close 都会执行到这里一次。
    if (gen_var(req)) {
        free(gen_var(req)->request);
        free(gen_var(req)->response_data);
        // stream 只是持有 async_sock/async_ssl 指针的壳，先释放壳本身。
        free(gen_var(req)->stream);
        if (gen_var(req)->async_ssl) {
            // async_ssl 拥有并释放它 attach 的 async_sock。
            async_ssl_destroy(gen_var(req)->async_ssl);
        } else if (gen_var(req)->async_sock) {
            anet_socket_close(gen_var(req)->async_sock);
            free(gen_var(req)->async_sock);
        } else if (anet_palsock_is_valid(gen_var(req)->sock)) {
            anet_palsock_close(gen_var(req)->sock);
        }
        free(gen_var(req));
        gen_var(req) = NULL;
    }
    gen_end(NULL);
}

// 公开入口: 内部协程 anet_async_http_request_ 直接把 req 当 arg 用 (借用,
// 调用方须保证 req 及其指向的字符串在 task 跑完前存活)。
task_t* anet_async_http_request(anet_async_http_request_t *req) {
    return anet_async_http_request_(req);
}

/* ============================================================
 * 流式 (SSE) 客户端实现
 * ============================================================ */

// 流式请求内部状态 (连接部分同 async_http_internal_t, 另加 SSE 行解析)
typedef struct {
    const char   *method;
    const char   *host;
    uint16_t      port;
    int           use_tls;
    const char   *path;
    const char  **headers;
    const char   *body;
    anet_sse_cb_t on_event;
    void         *userdata;

    // 连接状态
    anet_palsock_t sock;
    anet_socket_t *async_sock;
    async_ssl_t   *async_ssl;
    anet_stream_t *stream;
    char          *request;

    // SSE 行解析: 累积一行, 遇 '\n' 处理。跨 header/body 都按行扫,
    // header 行不以 "data:" 开头故被忽略, 天然跳过响应头。
    char          *linebuf;
    size_t         linebuf_len;
    size_t         linebuf_cap;
} stream_http_internal_t;

// on_emit 桥接: 驱动器把 gen_emit 的 anet_sse_event_t* 交到这里, 转调用户回调。
static void stream_emit_bridge(void *item, void *userdata) {
    stream_http_internal_t *st = (stream_http_internal_t*)userdata;
    if (st->on_event) {
        st->on_event((const anet_sse_event_t*)item, st->userdata);
    }
}

// 往行缓冲追加一个字节, 保持 NUL 结尾。失败返回 -1。
static int sse_linebuf_push(stream_http_internal_t *st, char c) {
    if (st->linebuf_len + 2 > st->linebuf_cap) {
        size_t ncap = st->linebuf_cap ? st->linebuf_cap * 2 : 256;
        char *nb = realloc(st->linebuf, ncap);
        if (!nb) return -1;
        st->linebuf = nb;
        st->linebuf_cap = ncap;
    }
    st->linebuf[st->linebuf_len++] = c;
    st->linebuf[st->linebuf_len] = '\0';
    return 0;
}

task_t* task_arg(anet_async_http_stream_) {
    gen_dec_vars(
        stream_http_internal_t *st;
        future_t         *fut;
        future_t         *resolve_fut;
        task_t           *task;
        struct sockaddr_storage addr;
        int               addr_len;
        char              buffer[HTTP_BUFFER_SIZE];
        int               bytes_read;
        int               i;
        anet_sse_event_t  ev;   /* 跨 gen_emit 存活 (data 指向持久 linebuf) */
    );
    gen_begin(ctx);

    {
        /* 本 task 由 task_run 顶层驱动 (emit 不能穿 gen_yield_from, 必须顶层),
         * 首次 gen_send 的 arg 为 NULL —— 从 userdata 取参数, 不能用 arg。 */
        stream_http_internal_t *in = (stream_http_internal_t*)gen_userdata();
        gen_var(st) = in;   /* 已由 anet_async_http_stream 堆分配并填好 */
        gen_var(st)->sock = -1;
    }

    // 解析地址
    gen_var(resolve_fut) = anet_palsock_resolve_async(gen_var(st)->host, AF_UNSPEC);
    if (!gen_var(resolve_fut)) {
        gen_return(anet_res_status(ANET_ERR));
    }
    gen_yield(gen_var(resolve_fut));
    {
        anet_resolve_result_t *r = (anet_resolve_result_t*)future_result(gen_var(resolve_fut));
        if (!r || r->ok != 0) {
            free(r);
            gen_return(anet_res_status(ANET_ERR));
        }
        gen_var(addr) = r->addr;
        gen_var(addr_len) = r->addr_len;
        free(r);
    }
    if (gen_var(addr).ss_family == AF_INET) {
        ((struct sockaddr_in*)&gen_var(addr))->sin_port = htons(gen_var(st)->port);
    } else if (gen_var(addr).ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&gen_var(addr))->sin6_port = htons(gen_var(st)->port);
    }

    // 建 socket + 连接
    gen_var(st)->sock = anet_palsock_create(gen_var(addr).ss_family, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(st)->sock)) {
        gen_return(anet_res_status(ANET_ERR));
    }
    gen_var(st)->async_sock = anet_socket_create(gen_var(st)->sock);
    if (!gen_var(st)->async_sock) {
        gen_return(anet_res_status(ANET_ERR));
    }
    gen_var(fut) = anet_socket_connect(gen_var(st)->async_sock, (struct sockaddr*)&gen_var(addr), gen_var(addr_len));
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) {
        gen_return(anet_res_status(ANET_ERR));
    }

    // TLS (wss/https 流)
    if (gen_var(st)->use_tls) {
        gen_var(st)->async_ssl = async_ssl_create(ASYNC_SSL_CLIENT, gen_var(st)->host);
        if (!gen_var(st)->async_ssl) {
            gen_return(anet_res_status(ANET_ERR));
        }
        async_ssl_attach_socket(gen_var(st)->async_ssl, gen_var(st)->async_sock);
        gen_var(task) = async_ssl_handshake(gen_var(st)->async_ssl);
        gen_yield_from_task(gen_var(task));
        if (anet_code_of(future_result(gen_var(task)->future)) != 0) {
            gen_return(anet_res_status(ANET_ERR));
        }
        gen_var(st)->stream = anet_stream_from_ssl(gen_var(st)->async_ssl);
    } else {
        gen_var(st)->stream = anet_stream_from_socket(gen_var(st)->async_sock);
    }
    if (!gen_var(st)->stream) {
        gen_return(anet_res_status(ANET_ERR));
    }

    // 发请求
    gen_var(st)->request = create_request_string(
        gen_var(st)->method, gen_var(st)->host, gen_var(st)->port,
        gen_var(st)->path, gen_var(st)->headers, gen_var(st)->body);
    if (!gen_var(st)->request) {
        gen_return(anet_res_status(ANET_ERR));
    }
    gen_var(task) = anet_stream_write_all(gen_var(st)->stream, gen_var(st)->request, strlen(gen_var(st)->request));
    gen_yield_from_task(gen_var(task));
    if (anet_code_of(future_result(gen_var(task)->future)) != 0) {
        gen_return(anet_res_status(ANET_ERR));
    }
    free(gen_var(st)->request);
    gen_var(st)->request = NULL;

    // 流式读取: 循环读, 按行喂解析器, 每个 "data:" 行 gen_emit 一个事件。
    while (1) {
        gen_var(task) = anet_stream_read(gen_var(st)->stream, sizeof(gen_var(buffer)), gen_var(buffer));
        gen_yield_from_task(gen_var(task));
        gen_var(bytes_read) = (int)anet_code_of(future_result(gen_var(task)->future));
        if (gen_var(bytes_read) <= 0) {
            // 对端关闭或出错 —— 流正常结束。
            gen_return(anet_res_status(ANET_OK));
        }

        for (gen_var(i) = 0; gen_var(i) < gen_var(bytes_read); gen_var(i)++) {
            char c = gen_var(buffer)[gen_var(i)];
            if (c == '\n') {
                // 一行完成: 去掉结尾 '\r', 判断是否 data: 行。
                char *line = gen_var(st)->linebuf;
                size_t llen = gen_var(st)->linebuf_len;
                if (llen > 0 && line[llen-1] == '\r') { line[--llen] = '\0'; }
                if (llen >= 5 && strncmp(line, "data:", 5) == 0) {
                    char *d = line + 5;
                    while (*d == ' ') d++;   // 去 "data:" 后可选空格
                    gen_var(ev).data = d;
                    gen_var(ev).len = strlen(d);
                    gen_emit(&gen_var(ev));   // 交付事件 (回调内有效)
                }
                gen_var(st)->linebuf_len = 0;
                if (gen_var(st)->linebuf) gen_var(st)->linebuf[0] = '\0';
            } else {
                if (sse_linebuf_push(gen_var(st), c) != 0) {
                    gen_return(anet_res_status(ANET_ERR));
                }
            }
        }
    }

    gen_cleanup();
    if (gen_var(st)) {
        free(gen_var(st)->request);
        free(gen_var(st)->linebuf);
        free(gen_var(st)->stream);   // 壳
        if (gen_var(st)->async_ssl) {
            async_ssl_destroy(gen_var(st)->async_ssl);
        } else if (gen_var(st)->async_sock) {
            anet_socket_close(gen_var(st)->async_sock);
            free(gen_var(st)->async_sock);
        } else if (anet_palsock_is_valid(gen_var(st)->sock)) {
            anet_palsock_close(gen_var(st)->sock);
        }
        free(gen_var(st));
        gen_var(st) = NULL;
    }
    gen_end(NULL);
}

task_t* anet_async_http_stream(anet_async_http_request_t *req,
                               anet_sse_cb_t on_event, void *userdata) {
    if (!req) return NULL;
    stream_http_internal_t *st = calloc(1, sizeof(*st));
    if (!st) return NULL;
    st->method   = req->method;
    st->host     = req->host;
    st->port     = req->port;
    st->use_tls  = req->use_tls;
    st->path     = req->path;
    st->headers  = req->headers;
    st->body     = req->body;
    st->on_event = on_event;
    st->userdata = userdata;

    task_t *t = anet_async_http_stream_(st);
    if (!t) { free(st); return NULL; }
    task_set_on_emit(t, stream_emit_bridge, st);
    return t;
}

/* ============================================================
 * 通用二进制流读取 (raw stream) 实现
 * ============================================================ */

typedef struct {
    const char          *method;
    const char          *host;
    uint16_t             port;
    int                  use_tls;
    const char          *path;
    const char         **headers;
    const char          *body;
    anet_http_chunk_cb_t on_chunk;
    void                *userdata;

    anet_palsock_t sock;
    anet_socket_t *async_sock;
    async_ssl_t   *async_ssl;
    anet_stream_t *stream;
    char          *request;

    // header 跳过状态: 累积响应头直到 \r\n\r\n, 之后 body 字节直接透传。
    char          *hdrbuf;
    size_t         hdrbuf_len;
    size_t         hdrbuf_cap;
    int            header_done;
} raw_stream_internal_t;

static void raw_emit_bridge(void *item, void *userdata) {
    raw_stream_internal_t *st = (raw_stream_internal_t*)userdata;
    if (st->on_chunk) {
        st->on_chunk((const anet_http_chunk_t*)item, st->userdata);
    }
}

// 往 header 缓冲追加一段字节, 保持 NUL 结尾 (供 strstr 找 \r\n\r\n)。失败返回 -1。
static int raw_hdr_push(raw_stream_internal_t *st, const char *p, size_t n) {
    if (st->hdrbuf_len + n + 1 > st->hdrbuf_cap) {
        size_t ncap = st->hdrbuf_cap ? st->hdrbuf_cap * 2 : 1024;
        while (ncap < st->hdrbuf_len + n + 1) ncap *= 2;
        char *nb = realloc(st->hdrbuf, ncap);
        if (!nb) return -1;
        st->hdrbuf = nb;
        st->hdrbuf_cap = ncap;
    }
    memcpy(st->hdrbuf + st->hdrbuf_len, p, n);
    st->hdrbuf_len += n;
    st->hdrbuf[st->hdrbuf_len] = '\0';
    return 0;
}

task_t* task_arg(anet_async_http_stream_raw_) {
    gen_dec_vars(
        raw_stream_internal_t *st;
        future_t         *fut;
        future_t         *resolve_fut;
        task_t           *task;
        struct sockaddr_storage addr;
        int               addr_len;
        char              buffer[HTTP_BUFFER_SIZE];
        int               bytes_read;
        anet_http_chunk_t chunk;   /* 跨 gen_emit 存活 */
    );
    gen_begin(ctx);

    {
        /* 顶层驱动: arg 为 NULL, 从 userdata 取参数 (同 SSE, 见 gen_emit 约束)。 */
        gen_var(st) = (raw_stream_internal_t*)gen_userdata();
        gen_var(st)->sock = -1;
    }

    gen_var(resolve_fut) = anet_palsock_resolve_async(gen_var(st)->host, AF_UNSPEC);
    if (!gen_var(resolve_fut)) { gen_return(anet_res_status(ANET_ERR)); }
    gen_yield(gen_var(resolve_fut));
    {
        anet_resolve_result_t *r = (anet_resolve_result_t*)future_result(gen_var(resolve_fut));
        if (!r || r->ok != 0) { free(r); gen_return(anet_res_status(ANET_ERR)); }
        gen_var(addr) = r->addr;
        gen_var(addr_len) = r->addr_len;
        free(r);
    }
    if (gen_var(addr).ss_family == AF_INET) {
        ((struct sockaddr_in*)&gen_var(addr))->sin_port = htons(gen_var(st)->port);
    } else if (gen_var(addr).ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&gen_var(addr))->sin6_port = htons(gen_var(st)->port);
    }

    gen_var(st)->sock = anet_palsock_create(gen_var(addr).ss_family, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(st)->sock)) { gen_return(anet_res_status(ANET_ERR)); }
    gen_var(st)->async_sock = anet_socket_create(gen_var(st)->sock);
    if (!gen_var(st)->async_sock) { gen_return(anet_res_status(ANET_ERR)); }
    gen_var(fut) = anet_socket_connect(gen_var(st)->async_sock, (struct sockaddr*)&gen_var(addr), gen_var(addr_len));
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) { gen_return(anet_res_status(ANET_ERR)); }
    if (gen_var(st)->use_tls) {
        gen_var(st)->async_ssl = async_ssl_create(ASYNC_SSL_CLIENT, gen_var(st)->host);
        if (!gen_var(st)->async_ssl) { gen_return(anet_res_status(ANET_ERR)); }
        async_ssl_attach_socket(gen_var(st)->async_ssl, gen_var(st)->async_sock);
        gen_var(task) = async_ssl_handshake(gen_var(st)->async_ssl);
        gen_yield_from_task(gen_var(task));
        if (anet_code_of(future_result(gen_var(task)->future)) != 0) { gen_return(anet_res_status(ANET_ERR)); }
        gen_var(st)->stream = anet_stream_from_ssl(gen_var(st)->async_ssl);
    } else {
        gen_var(st)->stream = anet_stream_from_socket(gen_var(st)->async_sock);
    }
    if (!gen_var(st)->stream) { gen_return(anet_res_status(ANET_ERR)); }

    gen_var(st)->request = create_request_string(
        gen_var(st)->method, gen_var(st)->host, gen_var(st)->port,
        gen_var(st)->path, gen_var(st)->headers, gen_var(st)->body);
    if (!gen_var(st)->request) { gen_return(anet_res_status(ANET_ERR)); }
    gen_var(task) = anet_stream_write_all(gen_var(st)->stream, gen_var(st)->request, strlen(gen_var(st)->request));
    gen_yield_from_task(gen_var(task));
    if (anet_code_of(future_result(gen_var(task)->future)) != 0) { gen_return(anet_res_status(ANET_ERR)); }
    free(gen_var(st)->request);
    gen_var(st)->request = NULL;

    // 读取: 先攒 header 到 \r\n\r\n, 之后 body 字节整块 emit。
    while (1) {
        gen_var(task) = anet_stream_read(gen_var(st)->stream, sizeof(gen_var(buffer)), gen_var(buffer));
        gen_yield_from_task(gen_var(task));
        gen_var(bytes_read) = (int)anet_code_of(future_result(gen_var(task)->future));
        if (gen_var(bytes_read) <= 0) {
            gen_return(anet_res_status(ANET_OK));   // 流结束
        }

        if (gen_var(st)->header_done) {
            gen_var(chunk).data = gen_var(buffer);
            gen_var(chunk).len  = (size_t)gen_var(bytes_read);
            gen_emit(&gen_var(chunk));
        } else {
            if (raw_hdr_push(gen_var(st), gen_var(buffer), (size_t)gen_var(bytes_read)) != 0) {
                gen_return(anet_res_status(ANET_ERR));
            }
            char *he = strstr(gen_var(st)->hdrbuf, "\r\n\r\n");
            if (he) {
                gen_var(st)->header_done = 1;
                size_t body_off = (size_t)((he + 4) - gen_var(st)->hdrbuf);
                if (gen_var(st)->hdrbuf_len > body_off) {
                    gen_var(chunk).data = gen_var(st)->hdrbuf + body_off;
                    gen_var(chunk).len  = gen_var(st)->hdrbuf_len - body_off;
                    gen_emit(&gen_var(chunk));
                }
            }
        }
    }

    gen_cleanup();
    if (gen_var(st)) {
        free(gen_var(st)->request);
        free(gen_var(st)->hdrbuf);
        free(gen_var(st)->stream);
        if (gen_var(st)->async_ssl) {
            async_ssl_destroy(gen_var(st)->async_ssl);
        } else if (gen_var(st)->async_sock) {
            anet_socket_close(gen_var(st)->async_sock);
            free(gen_var(st)->async_sock);
        } else if (anet_palsock_is_valid(gen_var(st)->sock)) {
            anet_palsock_close(gen_var(st)->sock);
        }
        free(gen_var(st));
        gen_var(st) = NULL;
    }
    gen_end(NULL);
}

task_t* anet_async_http_stream_raw(anet_async_http_request_t *req,
                                   anet_http_chunk_cb_t on_chunk, void *userdata) {
    if (!req) return NULL;
    raw_stream_internal_t *st = calloc(1, sizeof(*st));
    if (!st) return NULL;
    st->method   = req->method;
    st->host     = req->host;
    st->port     = req->port;
    st->use_tls  = req->use_tls;
    st->path     = req->path;
    st->headers  = req->headers;
    st->body     = req->body;
    st->on_chunk = on_chunk;
    st->userdata = userdata;

    task_t *t = anet_async_http_stream_raw_(st);
    if (!t) { free(st); return NULL; }
    task_set_on_emit(t, raw_emit_bridge, st);
    return t;
}

// 简化的异步GET请求
task_t* task_arg(anet_async_http_get_) {
    gen_dec_vars(
        const char *url;
        anet_async_http_response_t *response;
        parsed_url_t parsed;
        anet_async_http_request_t req;
        const char *headers[3];
        task_t *task;
    );
    gen_begin(ctx);

    {
        // 解析参数
        void **args = (void**)arg;
        gen_var(url) = (const char*)args[0];
        gen_var(response) = (anet_async_http_response_t*)args[1];
        free(args);

        if (parse_url(gen_var(url), &gen_var(parsed)) != 0) {
            gen_return(anet_res_status(ANET_ERR));
        }

        // 准备请求参数（headers 存于协程持久存储，跨 yield 有效）
        gen_var(headers)[0] = "User-Agent: asyncweb/0.1";
        gen_var(headers)[1] = "Accept: */*";
        gen_var(headers)[2] = NULL;
        gen_var(req).method = "GET";
        gen_var(req).host = gen_var(parsed).host;
        gen_var(req).port = gen_var(parsed).port;
        gen_var(req).use_tls = (strcmp(gen_var(parsed).scheme, "https") == 0);
        gen_var(req).path = gen_var(parsed).path;
        gen_var(req).headers = gen_var(headers);
        gen_var(req).body = NULL;
        gen_var(req).response = gen_var(response);
    }
    gen_var(task) = anet_async_http_request_(&gen_var(req));
    gen_yield_from_task(gen_var(task));

    gen_end(future_result(gen_var(task)->future));
}

task_t* anet_async_http_get(const char *url, anet_async_http_response_t *response) {
    void **args = malloc(2 * sizeof(void*));
    if (!args) return NULL;
    
    args[0] = (void*)url;
    args[1] = response;
    
    task_t *task = anet_async_http_get_(args);
    return task;
}

// 简化的异步POST请求
task_t* task_arg(anet_async_http_post_) {
    gen_dec_vars(
        const char *url;
        const char *content_type;
        const char *body;
        anet_async_http_response_t *response;
        parsed_url_t parsed;
        anet_async_http_request_t req;
        char ct_header[256];
        const char *headers[4];
        task_t *task;
    );
    gen_begin(ctx);

    {
        // 解析参数
        void **args = (void**)arg;
        gen_var(url) = (const char*)args[0];
        gen_var(content_type) = (const char*)args[1];
        gen_var(body) = (const char*)args[2];
        gen_var(response) = (anet_async_http_response_t*)args[3];
        free(args);
        
        if (parse_url(gen_var(url), &gen_var(parsed)) != 0) {
            gen_return(anet_res_status(ANET_ERR));
        }
        
        // 准备请求参数
        gen_var(headers)[0] = "User-Agent: asyncweb/0.1";
        gen_var(headers)[1] = NULL;
        gen_var(headers)[2] = NULL;
        gen_var(headers)[3] = NULL;
        
        if (gen_var(content_type)) {
            snprintf(gen_var(ct_header), sizeof(gen_var(ct_header)), "Content-Type: %s", gen_var(content_type));
            gen_var(headers)[1] = gen_var(ct_header);
        }
        
        gen_var(req).method = "POST";
        gen_var(req).host = gen_var(parsed).host;
        gen_var(req).port = gen_var(parsed).port;
        gen_var(req).use_tls = (strcmp(gen_var(parsed).scheme, "https") == 0);
        gen_var(req).path = gen_var(parsed).path;
        gen_var(req).headers = gen_var(headers);
        gen_var(req).body = gen_var(body);
        gen_var(req).response = gen_var(response);
    }

    gen_var(task) = anet_async_http_request_(&gen_var(req));
    gen_yield_from_task(gen_var(task));

    gen_end(future_result(gen_var(task)->future));
}

task_t* anet_async_http_post(const char *url, const char *content_type, const char *body, anet_async_http_response_t *response) {
    void **args = malloc(4 * sizeof(void*));
    if (!args) return NULL;
    
    args[0] = (void*)url;
    args[1] = (void*)content_type;
    args[2] = (void*)body;
    args[3] = response;
    
    task_t *task = anet_async_http_post_(args);
    return task;
}

// 释放异步HTTP响应资源
void anet_http_response_free(anet_async_http_response_t *response) {
    if (!response) return;
    
    free(response->status_text);
    free(response->headers);
    free(response->body);
    memset(response, 0, sizeof(*response));
}