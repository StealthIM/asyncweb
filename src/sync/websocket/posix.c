#include "sync/websocket.h"
#include "tls.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "tools.h"

struct anet_ws_t {
    int sock;
    char sec_key[64];
    int use_tls;
    anet_tls_ctx_t* tls;
};

// ================== 工具函数 ===================

// 简单 Base64 实现 (避免依赖 openssl/base64)
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const unsigned char* src, int len, char* out, int out_size) {
    int olen = 4 * ((len + 2) / 3);
    if (out_size < olen + 1) return -1;
    int i, j;
    for (i=0, j=0; i<len;) {
        uint32_t octet_a = i < len ? src[i++] : 0;
        uint32_t octet_b = i < len ? src[i++] : 0;
        uint32_t octet_c = i < len ? src[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > len)     ? '=' : b64_table[triple & 0x3F];
    }
    out[j] = '\0';
    return j;
}

static void generate_websocket_key(char out[64]) {
    unsigned char rand_bytes[16];
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(rand_bytes, 1, 16, f);
        fclose(f);
    } else {
        for (int i=0; i<16; i++) rand_bytes[i] = rand() & 0xFF;
    }
    base64_encode(rand_bytes, 16, out, 64);
}

static int parse_url(const char* url, int* is_tls, char* host, int* port, char* path) {
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
        *port = *is_tls ? 443 : 80;
    }

    strcpy(path, (*slash ? slash : "/"));
    return 0;
}

// ================== API 实现 ===================

void anet_ws_init() {
    anet_tls_init();
    srand(time(NULL));
}

anet_ws_t* anet_ws_connect(const char* url) {
    char host[256], path[256];
    int port, is_tls;
    if (parse_url(url, &is_tls, host, &port, path) != 0) return NULL;

    anet_ws_t* ws = calloc(1, sizeof(*ws));
    ws->use_tls = is_tls;

    if (is_tls) {
        ws->tls = anet_tls_create();
        if (!ws->tls) { free(ws); return NULL; }
        if (anet_tls_connect(ws->tls, host, port) != 0) {
            anet_tls_destroy(ws->tls);
            free(ws);
            return NULL;
        }
    } else {
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        char portstr[16];
        sprintf(portstr, "%d", port);

        if (getaddrinfo(host, portstr, &hints, &res) != 0) {
            free(ws);
            return NULL;
        }

        int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) { freeaddrinfo(res); free(ws); return NULL; }

        if (connect(s, res->ai_addr, res->ai_addrlen) != 0) {
            close(s);
            freeaddrinfo(res);
            free(ws);
            return NULL;
        }
        freeaddrinfo(res);
        ws->sock = s;
    }

    generate_websocket_key(ws->sec_key);

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

    int ret;
    if (is_tls)
        ret = anet_tls_send(ws->tls, req, strlen(req));
    else
        ret = send(ws->sock, req, strlen(req), 0);
    if (ret <= 0) { anet_ws_close(ws); return NULL; }

    char buf[1024];
    int n = is_tls ? anet_tls_recv(ws->tls, buf, sizeof(buf)-1)
                   : recv(ws->sock, buf, sizeof(buf)-1, 0);
    if (n <= 0) { anet_ws_close(ws); return NULL; }
    buf[n] = 0;

    if (!strstr(buf, "101") || !strcasestr(buf, "Sec-WebSocket-Accept")) {
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
        header[2] = (len >> 8) & 0xFF;
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
    for (int i=0; i<len; i++) frame[hlen+i] = ((char*)data)[i] ^ mask[i % 4];

    int ret = ws->use_tls ?
              anet_tls_send(ws->tls, frame, hlen + len) :
              send(ws->sock, frame, hlen + len, 0);
    free(frame);
    return (ret == hlen + len) ? ANET_WS_OK : ANET_WS_ERR;
}

int anet_ws_recv(anet_ws_t* ws, void* buffer, int maxlen, int* is_text) {
    if (!ws) return ANET_WS_ERR;

    unsigned char hdr[2];
    int n = ws->use_tls ? anet_tls_recv(ws->tls, (char*)hdr, 2)
                        : recv(ws->sock, (char*)hdr, 2, 0);
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
        unsigned char ext[2];
        if (ws->use_tls) anet_tls_recv(ws->tls, (char*)ext, 2);
        else recv(ws->sock, (char*)ext, 2, 0);
        len = (ext[0]<<8) | ext[1];
    } else if (len == 127) {
        return ANET_WS_ERR;
    }

    unsigned char mask[4];
    if (masked) {
        if (ws->use_tls) anet_tls_recv(ws->tls, (char*)mask, 4);
        else recv(ws->sock, (char*)mask, 4, 0);
    }

    if (len > maxlen) return ANET_WS_ERR;
    n = ws->use_tls ? anet_tls_recv(ws->tls, (char*)buffer, len)
                    : recv(ws->sock, (char*)buffer, len, 0);
    if (n != len) return ANET_WS_ERR;

    if (masked) {
        for (int i=0; i<len; i++)
            ((char*)buffer)[i] ^= mask[i % 4];
    }

    if (is_text) *is_text = (opcode == 0x1);
    return len;
}

void anet_ws_close(anet_ws_t* ws) {
    if (!ws) return;
    unsigned char closef[2] = {0x88, 0x00};
    if (ws->use_tls) {
        anet_tls_send(ws->tls, (char*)closef, 2);
        anet_tls_close(ws->tls);
        anet_tls_destroy(ws->tls);
    } else {
        send(ws->sock, (char*)closef, 2, 0);
        close(ws->sock);
    }
    free(ws);
}
