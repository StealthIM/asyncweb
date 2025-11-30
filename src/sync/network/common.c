#include <stdlib.h>
#include <string.h>

// 解码 chunked body，返回长度
int decode_chunked(const char* src, int src_len, char* dst, int dst_maxlen) {
    int offset = 0, dst_offset = 0;

    while (offset < src_len) {
        // 找到 \r\n
        const char* line_end = strstr(src + offset, "\r\n");
        if (!line_end) break;
        int line_len = line_end - (src + offset);
        char hex[32] = {0};
        if (line_len >= (int)sizeof(hex)) return -1;
        memcpy(hex, src + offset, line_len);
        int chunk_size = (int)strtol(hex, NULL, 16);
        if (chunk_size == 0) break; // 最后一块
        offset += line_len + 2; // 跳过 \r\n

        if (dst_offset + chunk_size >= dst_maxlen) return -1;
        memcpy(dst + dst_offset, src + offset, chunk_size);
        dst_offset += chunk_size;
        offset += chunk_size + 2; // 跳过 chunk + \r\n
    }
    dst[dst_offset] = '\0';
    return dst_offset;
}