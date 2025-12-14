#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "http.h"
#include "tls.h"
#include "sock/pal_socket.h"
#include "libcoro.h"

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
    
    // Host 头部
    if ((port == 80 && strcmp(method, "http") == 0) || 
        (port == 443 && strcmp(method, "https") == 0)) {
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
        async_http_response_t *response = (async_http_response_t*)response_ptr;
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
        sync_http_response_t *response = (sync_http_response_t*)response_ptr;
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
int sync_http_request(const char *method,
                     const char *host,
                     uint16_t port,
                     const char *path,
                     const char **headers,
                     const char *body,
                     sync_http_response_t *response) {
    if (!method || !host || !path || !response) return -1;
    
    // 初始化响应结构
    memset(response, 0, sizeof(*response));
    
    // 初始化平台socket
    anet_palsock_init();
    
    // 创建socket
    anet_palsock_t sock = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 0);
    if (!anet_palsock_is_valid(sock)) {
        anet_palsock_cleanup();
        return -1;
    }
    
    // 解析地址
    struct sockaddr_storage addr;
    int addr_len;
    if (anet_palsock_resolve(host, &addr, &addr_len) != 0) {
        anet_palsock_close(sock);
        anet_palsock_cleanup();
        return -1;
    }
    
    // 设置端口
    if (addr.ss_family == AF_INET) {
        ((struct sockaddr_in*)&addr)->sin_port = htons(port);
    } else if (addr.ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&addr)->sin6_port = htons(port);
    }
    
    // 连接
    if (anet_palsock_connect(sock, (struct sockaddr*)&addr, addr_len) != 0) {
        anet_palsock_close(sock);
        anet_palsock_cleanup();
        return -1;
    }
    
    // 创建stream
    sync_stream_t *stream = NULL;
    int is_ssl = (port == 443);
    
    if (is_ssl) {
        // 创建SSL
        sync_ssl_t *ssl = sync_ssl_create(SYNC_SSL_CLIENT, host);
        if (!ssl) {
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return -1;
        }
        
        sync_ssl_attach_socket(ssl, sock);
        
        // SSL握手
        if (sync_ssl_handshake(ssl) != 0) {
            sync_ssl_destroy(ssl);
            anet_palsock_close(sock);
            anet_palsock_cleanup();
            return -1;
        }
        
        stream = sync_stream_from_ssl(ssl);
    } else {
        stream = sync_stream_from_socket(sock);
    }
    
    if (!stream) {
        if (is_ssl) {
            sync_ssl_destroy(sync_stream_get_ssl(stream));
        }
        anet_palsock_close(sock);
        anet_palsock_cleanup();
        return -1;
    }
    
    // 创建请求
    char *request = create_request_string(method, host, port, path, headers, body);
    if (!request) {
        sync_stream_destroy(stream);
        anet_palsock_cleanup();
        return -1;
    }
    
    // 发送请求
    if (sync_stream_write(stream, request, strlen(request)) != 0) {
        free(request);
        sync_stream_destroy(stream);
        anet_palsock_cleanup();
        return -1;
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
        
        // 扩展响应缓冲区
        if (total_read + bytes_read > response_capacity) {
            size_t new_capacity = response_capacity ? response_capacity * 2 : 4096;
            while (new_capacity < total_read + bytes_read) {
                new_capacity *= 2;
            }
            
            char *new_data = realloc(response_data, new_capacity);
            if (!new_data) {
                free(response_data);
                sync_stream_destroy(stream);
                anet_palsock_cleanup();
                return -1;
            }
            
            response_data = new_data;
            response_capacity = new_capacity;
        }
        
        // 复制数据
        memcpy(response_data + total_read, buffer, bytes_read);
        total_read += bytes_read;
        
        // 检查是否读取完整（简单检查，实际应该根据Content-Length）
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
    
    return result;
}

// 释放 HTTP 响应资源
void sync_http_response_free(sync_http_response_t *response) {
    if (!response) return;
    
    free(response->status_text);
    free(response->headers);
    free(response->body);
    memset(response, 0, sizeof(*response));
}

// 简化的 GET 请求
int sync_http_get(const char *url, sync_http_response_t *response) {
    parsed_url_t parsed;
    if (parse_url(url, &parsed) != 0) return -1;
    
    const char *headers[] = { "User-Agent: asyncweb/0.1", "Accept: */*", NULL };
    return sync_http_request("GET", parsed.host, parsed.port, parsed.path, headers, NULL, response);
}

// 简化的 POST 请求
int sync_http_post(const char *url, const char *content_type, const char *body, sync_http_response_t *response) {
    parsed_url_t parsed;
    if (parse_url(url, &parsed) != 0) return -1;
    
    const char *headers[4] = { "User-Agent: asyncweb/0.1", NULL, NULL, NULL };
    
    if (content_type) {
        char ct_header[256];
        snprintf(ct_header, sizeof(ct_header), "Content-Type: %s", content_type);
        headers[1] = ct_header;
    }
    
    return sync_http_request("POST", parsed.host, parsed.port, parsed.path, headers, body, response);
}

/* ============================================================
 * 异步HTTP实现
 * ============================================================ */

// 异步HTTP请求参数扩展
typedef struct {
    const char *method;
    const char *host;
    uint16_t port;
    const char *path;
    const char **headers;
    const char *body;
    async_http_response_t *response;
    
    // 内部状态
    parsed_url_t parsed;
    anet_palsock_t sock;
    async_socket_t *async_sock;
    async_ssl_t *async_ssl;
    async_stream_t *stream;
    char *request;
    char *response_data;
    size_t response_capacity;
    size_t total_read;
} async_http_internal_t;

// 异步HTTP请求协程
task_t* task_arg(async_http_request_) {
    gen_dec_vars(
        async_http_internal_t *req;
        future_t *fut;
        task_t *task;
        char buffer[HTTP_BUFFER_SIZE];
        int bytes_read;
    );
    gen_begin(ctx);

    {
        async_http_request_t *in = (async_http_request_t*)arg;
        
        // 创建内部请求结构
        gen_var(req) = calloc(1, sizeof(*gen_var(req)));
        if (!gen_var(req)) {
            gen_return((void*)(intptr_t)-1);
        }
        
        // 复制参数
        gen_var(req)->method = in->method;
        gen_var(req)->host = in->host;
        gen_var(req)->port = in->port;
        gen_var(req)->path = in->path;
        gen_var(req)->headers = in->headers;
        gen_var(req)->body = in->body;
        gen_var(req)->response = in->response;
        
        // 初始化响应结构
        memset(gen_var(req)->response, 0, sizeof(*gen_var(req)->response));

        gen_var(req)->sock = -1;
    }

    // 步骤1: 创建socket
    gen_var(req)->sock = anet_palsock_create(AF_INET, SOCK_STREAM, 0, 1);
    if (!anet_palsock_is_valid(gen_var(req)->sock)) {
        gen_return((void*)(intptr_t)-1);
    }

    // 步骤2: 解析地址
    struct sockaddr_storage addr;
    int addr_len;
    if (anet_palsock_resolve(gen_var(req)->host, &addr, &addr_len) != 0) {
        gen_return((void*)(intptr_t)-1);
    }

    // 设置端口
    if (addr.ss_family == AF_INET) {
        ((struct sockaddr_in*)&addr)->sin_port = htons(gen_var(req)->port);
    } else if (addr.ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&addr)->sin6_port = htons(gen_var(req)->port);
    }

    // 创建异步socket
    gen_var(req)->async_sock = async_socket_create(gen_var(req)->sock);
    if (!gen_var(req)->async_sock) {
        gen_return((void*)(intptr_t)-1);
    }

    // 步骤3: 连接
    gen_var(fut) = async_socket_connect(gen_var(req)->async_sock, (struct sockaddr*)&addr, addr_len);
    gen_yield(gen_var(fut));
    if (future_is_rejected(gen_var(fut))) {
        gen_return((void*)(intptr_t)-1);
    }

    // 步骤4: 创建SSL（如果是HTTPS）
    // TODO: fix
    int is_ssl = (gen_var(req)->port == 443);

    if (is_ssl) {
        gen_var(req)->async_ssl = async_ssl_create(ASYNC_SSL_CLIENT, gen_var(req)->host);
        if (!gen_var(req)->async_ssl) {
            gen_return((void*)(intptr_t)-1);
        }

        async_ssl_attach_socket(gen_var(req)->async_ssl, gen_var(req)->async_sock);

        // 步骤5: SSL握手
        gen_var(task) = async_ssl_handshake(gen_var(req)->async_ssl);
        gen_yield_from_task(gen_var(task));

        if (future_result(gen_var(task)->future) != (void*)0) {
            gen_return((void*)(intptr_t)-1);
        }

        gen_var(req)->stream = async_stream_from_ssl(gen_var(req)->async_ssl);
        if (!gen_var(req)->stream) {
            gen_return((void*)(intptr_t)-1);
        }

    } else {
        gen_var(req)->stream = async_stream_from_socket(gen_var(req)->async_sock);
        if (!gen_var(req)->stream) {
            gen_return((void*)(intptr_t)-1);
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
        gen_return((void*)(intptr_t)-1);
    }

    // 步骤7: 发送请求
    gen_var(task) = async_stream_write_all(gen_var(req)->stream, gen_var(req)->request, strlen(gen_var(req)->request));
    gen_yield_from_task(gen_var(task));

    if (future_result(gen_var(task)->future) != (void*)0) {
        gen_return((void*)(intptr_t)-1);
    }

    free(gen_var(req)->request);
    gen_var(req)->request = NULL;

    // 步骤8: 读取响应
    while (1) {
        gen_var(task) = async_stream_read(gen_var(req)->stream, sizeof(gen_var(buffer)), gen_var(buffer));
        gen_yield_from_task(gen_var(task));
        
        gen_var(bytes_read) = (int)(intptr_t)future_result(gen_var(task)->future);
        if (gen_var(bytes_read) <= 0) {
            // 读取完成，解析响应
            if (gen_var(req)->total_read > 0) {
                int result = parse_response(gen_var(req)->response_data, gen_var(req)->total_read, gen_var(req)->response, 1);
                free(gen_var(req)->response_data);
                gen_var(req)->response_data = NULL;
                gen_return((void*)(intptr_t)result);
            }
            gen_return((void*)(intptr_t)-1);
        }
        
        // 扩展响应缓冲区
        if (gen_var(req)->total_read + gen_var(bytes_read) > gen_var(req)->response_capacity) {
            size_t new_capacity = gen_var(req)->response_capacity ? gen_var(req)->response_capacity * 2 : 4096;
            while (new_capacity < gen_var(req)->total_read + gen_var(bytes_read)) {
                new_capacity *= 2;
            }
            
            char *new_data = realloc(gen_var(req)->response_data, new_capacity);
            if (!new_data) {
                free(gen_var(req)->response_data);
                gen_return((void*)(intptr_t)-1);
            }
            
            gen_var(req)->response_data = new_data;
            gen_var(req)->response_capacity = new_capacity;
        }
        
        // 复制数据
        memcpy(gen_var(req)->response_data + gen_var(req)->total_read, gen_var(buffer), gen_var(bytes_read));
        gen_var(req)->total_read += gen_var(bytes_read);
        
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
                    free(gen_var(req)->response_data);
                    gen_var(req)->response_data = NULL;
                    gen_return((void*)(intptr_t)result);
                }
            }
        }
    }
        // 继续读取
        // 不改变step，继续循环
    gen_end(NULL);
}

// 简化的异步GET请求
task_t* task_arg(async_http_get_) {
    gen_dec_vars(
        const char *url;
        async_http_response_t *response;
        parsed_url_t parsed;
        async_http_request_t req;
        task_t *task;
    );
    gen_begin(ctx);

    {
        // 解析参数
        void **args = (void**)arg;
        gen_var(url) = (const char*)args[0];
        gen_var(response) = (async_http_response_t*)args[1];
        free(args);
        
        if (parse_url(gen_var(url), &gen_var(parsed)) != 0) {
            gen_return((void*)(intptr_t)-1);
        }
        
        // 准备请求参数
        const char *headers[] = { "User-Agent: asyncweb/0.1", "Accept: */*", NULL };
        gen_var(req).method = "GET";
        gen_var(req).host = gen_var(parsed).host;
        gen_var(req).port = gen_var(parsed).port;
        gen_var(req).path = gen_var(parsed).path;
        gen_var(req).headers = headers;
        gen_var(req).body = NULL;
        gen_var(req).response = gen_var(response);
    }
    gen_var(task) = async_http_request_(&gen_var(req));
    gen_yield_from_task(gen_var(task));

    gen_end(future_result(gen_var(task)->future));
}

task_t* async_http_get(const char *url, async_http_response_t *response) {
    void **args = malloc(2 * sizeof(void*));
    if (!args) return NULL;
    
    args[0] = (void*)url;
    args[1] = response;
    
    task_t *task = async_http_get_(args);
    return task;
}

// 简化的异步POST请求
task_t* task_arg(async_http_post_) {
    gen_dec_vars(
        const char *url;
        const char *content_type;
        const char *body;
        async_http_response_t *response;
        parsed_url_t parsed;
        async_http_request_t req;
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
        gen_var(response) = (async_http_response_t*)args[3];
        free(args);
        
        if (parse_url(gen_var(url), &gen_var(parsed)) != 0) {
            gen_return((void*)(intptr_t)-1);
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
        gen_var(req).path = gen_var(parsed).path;
        gen_var(req).headers = gen_var(headers);
        gen_var(req).body = gen_var(body);
        gen_var(req).response = gen_var(response);
    }

    gen_var(task) = async_http_request_(&gen_var(req));
    gen_yield_from_task(gen_var(task));

    gen_end(future_result(gen_var(task)->future));
}

task_t* async_http_post(const char *url, const char *content_type, const char *body, async_http_response_t *response) {
    void **args = malloc(4 * sizeof(void*));
    if (!args) return NULL;
    
    args[0] = (void*)url;
    args[1] = (void*)content_type;
    args[2] = (void*)body;
    args[3] = response;
    
    task_t *task = async_http_post_(args);
    return task;
}

// 释放异步HTTP响应资源
void async_http_response_free(async_http_response_t *response) {
    if (!response) return;
    
    free(response->status_text);
    free(response->headers);
    free(response->body);
    memset(response, 0, sizeof(*response));
}