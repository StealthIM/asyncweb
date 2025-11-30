#include "tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <libcoro.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#endif

struct anet_tls_ctx {
    SSL* ssl;
    SSL_CTX* ctx;
#ifdef _WIN32
    SOCKET sock;
#else
    int sock;
#endif
};

int anet_tls_init(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    return 0;
}

int anet_tls_cleanup(void) {
    EVP_cleanup();
    return 0;
}

anet_tls_ctx_t* anet_tls_create(void) {
    anet_tls_ctx_t* t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    t->ctx = SSL_CTX_new(TLS_client_method());
    if (!t->ctx) {
        free(t);
        return NULL;
    }
    return t;
}

void anet_tls_destroy(anet_tls_ctx_t* ctx) {
    if (!ctx) return;
    if (ctx->ssl) SSL_free(ctx->ssl);
    if (ctx->ctx) SSL_CTX_free(ctx->ctx);
#ifdef _WIN32
    if (ctx->sock) closesocket(ctx->sock);
#else
    if (ctx->sock >= 0) close(ctx->sock);
#endif
    free(ctx);
}

int anet_tls_connect(anet_tls_ctx_t* ctx, const char* host, int port) {
    if (!ctx) return -1;

    // 创建普通 TCP socket
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    ctx->sock = socket(AF_INET, SOCK_STREAM, 0);
#else
    ctx->sock = -1;
#endif

    struct addrinfo hints, *res;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

#ifdef _WIN32
    if (connect(ctx->sock, res->ai_addr, res->ai_addrlen) < 0) { freeaddrinfo(res); return -1; }
#else
    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) { freeaddrinfo(res); return -1; }
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) { close(sockfd); freeaddrinfo(res); return -1; }
    ctx->sock = sockfd;
#endif
    freeaddrinfo(res);

    // 创建 SSL 连接
    ctx->ssl = SSL_new(ctx->ctx);
    if (!ctx->ssl) return -1;
    SSL_set_fd(ctx->ssl, ctx->sock);
    SSL_set_tlsext_host_name(ctx->ssl, host);
    if (SSL_connect(ctx->ssl) <= 0) {
        SSL_free(ctx->ssl);
        ctx->ssl = NULL;
        return -1;
    }
    return 0;
}

// #ifdef _WIN32
// int set_nonblocking(SOCKET sock) {
//     u_long mode = 1;
//     return ioctlsocket(sock, FIONBIO, &mode);
// }
// #else
// int set_nonblocking(int sock) {
//     int flags = fcntl(sock, F_GETFL, 0);
//     if (flags == -1) return -1;
//     return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
// }
// #endif
//
// int _anet_tls_connect_async(task_t *task, task_ctx_t *userdata);
// typedef struct _anet_tls_connect_ctx {
//     anet_tls_ctx_t* ctx;
//     const char* host;
//     int port;
// } _anet_tls_connect_ctx_t;
//
// int _anet_tls_connect_async(task_t *task, task_ctx_t *ctx) {
//     task_local_var(
//         anet_tls_ctx_t* ctx;
//         const char* host;
//         int port;
//         struct addrinfo *res;
//     );
//     task_enter();
//     _anet_tls_connect_ctx_t* data = task_userdata(_anet_tls_connect_ctx_t*);
//     task_var(ctx) = data->ctx;
//     task_var(host) = data->host;
//     task_var(port) = data->port;
//     free(data);
//
// #ifdef _WIN32
//     WSADATA wsa;
//     WSAStartup(MAKEWORD(2,2), &wsa);
//     ctx->sock = socket(AF_INET, SOCK_STREAM, 0);
// #else
//     ctx->sock = -1;
// #endif
//
//      set_nonblocking(ctx->sock);
//
//      struct addrinfo hints;
//      char port_str[6];
//      snprintf(port_str, sizeof(port_str), "%d", port);
//      memset(&hints, 0, sizeof(hints));
//      hints.ai_family = AF_UNSPEC;
//      hints.ai_socktype = SOCK_STREAM;
//
//      if (getaddrinfo(host, port_str, &hints, &task_var(res)) != 0) {
//          task_return(-1);
//      }
//
//     if (connect(ctx->sock, task_var(res)->ai_addr, task_var(res)->ai_addrlen) < 0) {
// #ifdef _WIN32
//         bool err = WSAGetLastError() != WSAEWOULDBLOCK;
// #else
//         bool err = errno != EWOULDBLOCK;
// #endif
//         if (err) {
//             freeaddrinfo(task_var(res));
//             task_return(-1);
//         }
//         task_register_handle(ctx->sock);
//         freeaddrinfo(task_var(res));
//
//         task_var(ctx)->ssl = SSL_new(task_var(ctx)->ctx);
//         if (!task_var(ctx)->ssl) {
//             task_return(-1);
//         }
//         SSL_set_fd(task_var(ctx)->ssl, task_var(ctx)->sock);
//         SSL_set_tlsext_host_name(task_var(ctx)->ssl, task_var(host));
//         int ret = SSL_connect(task_var(ctx)->ssl);
//
//     }
//     task_end();
// }
//
// task_t *anet_tls_connect_async(loop_t *loop, anet_tls_ctx_t* ctx, const char* host, int port) {
//     _anet_tls_connect_ctx_t *data = calloc(1, sizeof(_anet_tls_connect_ctx_t));
//     if (!data) return NULL;
//     data->ctx = ctx;
//     data->host = host;
//     data->port = port;
//     return task_create(loop, _anet_tls_connect_async, data);
// }

void anet_tls_close(anet_tls_ctx_t* ctx) {
    if (!ctx) return;
    if (ctx->ssl) SSL_shutdown(ctx->ssl);
#ifdef _WIN32
    if (ctx->sock) closesocket(ctx->sock);
#else
    if (ctx->sock >= 0) close(ctx->sock);
#endif
}

int anet_tls_send(anet_tls_ctx_t* ctx, const char* buf, int len) {
    if (!ctx || !ctx->ssl) return -1;
    return SSL_write(ctx->ssl, buf, len);
}

int anet_tls_recv(anet_tls_ctx_t* ctx, char* buf, int maxlen) {
    if (!ctx || !ctx->ssl) return -1;
    return SSL_read(ctx->ssl, buf, maxlen);
}
