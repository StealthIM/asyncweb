#include "../../include/private/sock/pal_socket.h"

#include <ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>

// ======================
// 错误转换
// ======================

anet_palsock_err_t anet_palsock_translate_error(int e)
{
    switch (e) {
        case WSAEWOULDBLOCK:
            return PALSOCK_ERR_AGAIN;
        case WSAECONNRESET:
            return PALSOCK_ERR_CONN_RESET;
        case WSAENOTCONN:
        case WSAESHUTDOWN:
            return PALSOCK_ERR_CLOSED;
        case WSAEADDRNOTAVAIL:
        case WSAEADDRINUSE:
            return PALSOCK_ERR_ADDR;
        case WSAENETDOWN:
        case WSAENETUNREACH:
            return PALSOCK_ERR_NETDOWN;
        case WSAEINPROGRESS:
            return PALSOCK_ERR_IN_PROGRESS;
        default:
            return PALSOCK_ERR_UNKNOWN;
    }
}

void anet_palsock_init()
{
    WSADATA w;
    WSAStartup(MAKEWORD(2,2), &w);
}

void anet_palsock_cleanup()
{
    WSACleanup();
}


// ======================
// 基础操作
// ======================

anet_palsock_t anet_palsock_create(int af, int type, int protocol, int async)
{
    return WSASocket(af, type, protocol, NULL, 0, async?WSA_FLAG_OVERLAPPED:0);
}

void anet_palsock_close(anet_palsock_t s)
{
    if (s != INVALID_SOCKET)
        closesocket(s);
}

int anet_palsock_is_valid(anet_palsock_t s)
{
    return s != INVALID_SOCKET;
}

int anet_palsock_set_nonblocking(anet_palsock_t s, int enabled)
{
    u_long mode = enabled ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode);
}

int anet_palsock_connect(anet_palsock_t s, const struct sockaddr *addr, int addrlen)
{
    return connect(s, addr, addrlen);
}

int anet_palsock_bind(anet_palsock_t s, const struct sockaddr *addr, int addrlen)
{
    return bind(s, addr, addrlen);
}

int anet_palsock_listen(anet_palsock_t s, int backlog)
{
    return listen(s, backlog);
}

anet_palsock_t anet_palsock_accept(anet_palsock_t s, struct sockaddr *addr, int *addrlen)
{
    return accept(s, addr, addrlen);
}


// ======================
// send/recv
// ======================

int anet_palsock_recv(anet_palsock_t s, void *buf, size_t len, int flags)
{
    int n = recv(s, buf, (int)len, flags);
    return (n >= 0) ? n : -WSAGetLastError();
}

int anet_palsock_send(anet_palsock_t s, const void *buf, size_t len, int flags)
{
    int n = send(s, buf, (int)len, flags);
    return (n >= 0) ? n : -WSAGetLastError();
}


// ======================
// DNS & 地址解析
// ======================

int anet_palsock_parse_addr(const char *host, uint16_t port,
                        struct sockaddr_storage *out_addr,
                        int *out_len)
{
    memset(out_addr, 0, sizeof(*out_addr));

    struct in_addr ipv4;
    if (InetPton(AF_INET, host, &ipv4) == 1) {
        struct sockaddr_in *addr4 = (struct sockaddr_in*)out_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        addr4->sin_addr = ipv4;
        *out_len = sizeof(struct sockaddr_in);
        return 0;
    }

    struct in6_addr ipv6;
    if (InetPton(AF_INET6, host, &ipv6) == 1) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)out_addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
        addr6->sin6_addr = ipv6;
        *out_len = sizeof(struct sockaddr_in6);
        return 0;
    }

    return anet_palsock_resolve(host, out_addr, out_len);
}

int anet_palsock_resolve(const char *hostname,
                     struct sockaddr_storage *out_addr,
                     int *out_len)
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res;
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
        return -1;

    memcpy(out_addr, res->ai_addr, res->ai_addrlen);
    *out_len = (int)res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}


// ======================
// socket 选项
// ======================

int anet_palsock_set_nodelay(anet_palsock_t s, int enabled)
{
    return setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                      (const char*)&enabled, sizeof(enabled));
}

int anet_palsock_set_reuseaddr(anet_palsock_t s, int enabled)
{
    return setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                      (const char*)&enabled, sizeof(enabled));
}

int anet_palsock_set_keepalive(anet_palsock_t s, int enabled)
{
    return setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                      (const char*)&enabled, sizeof(enabled));
}
