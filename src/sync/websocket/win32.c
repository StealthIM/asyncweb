#include "sync/websocket.h"
#include "tls.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "tools.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

struct anet_ws_t {
    SOCKET sock;
    char sec_key[64];
    int use_tls;
    anet_tls_ctx_t* tls;
};

// ================== 工具函数 ===================

static int base64_encode(const unsigned char* src, int len, char* out, int out_size) {
    DWORD out_len = out_size;
    if (!CryptBinaryToStringA(src, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &out_len))
        return -1;
    return (int)out_len - 1;
}

static void generate_websocket_key(char out[64]) {
    HCRYPTPROV hProv = 0;
    unsigned char rand_bytes[16];
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        for (int i=0; i<16; i++) rand_bytes[i] = (unsigned char)(rand() & 0xFF);
    } else {
        CryptGenRandom(hProv, 16, rand_bytes);
        CryptReleaseContext(hProv, 0);
    }
    base64_encode(rand_bytes, 16, out, 64);
}

static int parse_url(const char* url, int* is_tls, char* host, int* port, char* path) {
    // 支持 ws://host:port/path 和 wss://host:port/path
    if (strncmp(url, "ws://", 5) == 0) {
        *is_tls = 0;
        url += 5;
    } else if (strncmp(url, "wss://", 6) == 0) {
        *is_tls = 1;
        url += 6;
    } else {
        return -1;
    }

    const char* slash = strchr(url, '/');
    const char* colon = strchr(url, ':');
    if (!slash) slash = url + strlen(url);

    if (colon && colon < slash) {
        strncpy(host, url, colon - url);
        host[colon - url] = 0;
        *port = atoi(colon + 1);
    } else {
        strncpy(host, url, slash - url);
        host[slash - url] = 0;
        *port = *is_tls ? 443 : 80; // 默认端口
    }

    strcpy(path, *slash ? slash : "/");
    return 0;
}

// ================== API 实现 ===================

void anet_ws_init() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    anet_tls_init(); // 初始化 TLS 库
    srand(time(NULL));
}

anet_ws_t* anet_ws_connect(const char* url) {
    char host[256], path[256];
    int port, is_tls;
    if (parse_url(url, &is_tls, host, &port, path) != 0) return NULL;

    anet_ws_t* ws = calloc(1, sizeof(*ws));
    ws->use_tls = is_tls;

    if (is_tls) {
        // TLS 连接
        ws->tls = anet_tls_create();
        if (!ws->tls) {
            free(ws);
            return NULL;
        }
        if (anet_tls_connect(ws->tls, host, port) != 0) {
            anet_tls_destroy(ws->tls);
            free(ws);
            return NULL;
        }
    }
    else {
        // 普通 TCP 连接
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        char portstr[16];
        sprintf(portstr, "%d", port);

        if (getaddrinfo(host, portstr, &hints, &res) != 0) {
            free(ws);
            return NULL;
        }

        SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
            freeaddrinfo(res);
            closesocket(s);
            free(ws);
            return NULL;
        }
        freeaddrinfo(res);
        ws->sock = s;
    }

    // 生成 key
    generate_websocket_key(ws->sec_key);

    // 发送握手请求
    char req[1024];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, port, ws->sec_key);

    if (is_tls) {
        if (anet_tls_send(ws->tls, req, (int)strlen(req)) <= 0) {
            anet_tls_close(ws->tls);
            anet_tls_destroy(ws->tls);
            free(ws);
            return NULL;
        }
    }
    else {
        if (send(ws->sock, req, (int)strlen(req), 0) <= 0) {
            closesocket(ws->sock);
            free(ws);
            return NULL;
        }
    }

    // 读取响应
    char buf[1024];
    int n = is_tls ? anet_tls_recv(ws->tls, buf, sizeof(buf)-1)
                   : recv(ws->sock, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        anet_ws_close(ws);
        return NULL;
    }
    buf[n] = 0;

    if (strstr(buf, "101") == NULL || strcasestr(buf, "Sec-WebSocket-Accept") == NULL) {
        anet_ws_close(ws);
        return NULL;
    }

    return ws;
}

anet_ws_status_t anet_ws_send(anet_ws_t* ws, const void* data, int len, int is_text) {
    if (!ws) return ANET_WS_ERR;
    unsigned char header[10];
    int hlen = 0;

    header[0] = 0x80 | (is_text ? 0x1 : 0x2);
    if (len <= 125) {
        header[1] = 0x80 | (unsigned char)len;
        hlen = 2;
    } else if (len <= 65535) {
        header[1] = 0x80 | 126;
        header[2] = len >> 8 & 0xFF;
        header[3] = len & 0xFF;
        hlen = 4;
    } else {
        return ANET_WS_ERR;
    }

    unsigned char mask[4];
    for (int i=0; i<4; i++) mask[i] = rand() & 0xFF;
    memcpy(header + hlen, mask, 4);
    hlen += 4;

    char* frame = malloc(hlen + len);
    memcpy(frame, header, hlen);
    for (int i=0; i<len; i++) {
        frame[hlen+i] = ((char*)data)[i] ^ mask[i % 4];
    }

    int ret;
    if (ws->use_tls)
        ret = anet_tls_send(ws->tls, frame, hlen + len);
    else
        ret = send(ws->sock, frame, hlen + len, 0);

    free(frame);
    return ret == hlen + len ? ANET_WS_OK : ANET_WS_ERR;
}

int anet_ws_recv(anet_ws_t* ws, void* buffer, int maxlen, int* is_text) {
    if (!ws) return ANET_WS_ERR;

    char hdr[2];
    int n = ws->use_tls ? anet_tls_recv(ws->tls, hdr, 2)
                        : recv(ws->sock, hdr, 2, 0);
    if (n <= 0) return ANET_WS_CLOSED;

    int opcode = hdr[0] & 0x0F;
    int masked = (hdr[1] & 0x80) != 0;
    int len = hdr[1] & 0x7F;

    if (opcode == 0x8) return ANET_WS_CLOSED;
    if (opcode == 0x9) {
        char pong[2] = { (char)0x8A, 0x00 };
        if (ws->use_tls) anet_tls_send(ws->tls, pong, 2);
        else send(ws->sock, pong, 2, 0);
        return 0;
    }

    if (len == 126) {
        char ext[2];
        if (ws->use_tls) anet_tls_recv(ws->tls, ext, 2);
        else recv(ws->sock, ext, 2, 0);
        len = ext[0]<<8 | ext[1];
    } else if (len == 127) {
        return ANET_WS_ERR;
    }

    char mask[4];
    if (masked) {
        if (ws->use_tls) anet_tls_recv(ws->tls, mask, 4);
        else recv(ws->sock, mask, 4, 0);
    }

    if (len > maxlen) return ANET_WS_ERR;
    n = ws->use_tls ? anet_tls_recv(ws->tls, buffer, len)
                    : recv(ws->sock, buffer, len, 0);
    if (n != len) return ANET_WS_ERR;

    if (masked) {
        for (int i=0; i<len; i++) {
            ((char*)buffer)[i] ^= mask[i % 4];
        }
    }

    if (is_text) *is_text = opcode == 0x1;
    return len;
}

void anet_ws_close(anet_ws_t* ws) {
    if (!ws) return;
    char closef[2] = {0x88, 0x00};
    if (ws->use_tls) {
        anet_tls_send(ws->tls, closef, 2);
        anet_tls_close(ws->tls);
        anet_tls_destroy(ws->tls);
    } else {
        send(ws->sock, closef, 2, 0);
        closesocket(ws->sock);
    }
    free(ws);
}
