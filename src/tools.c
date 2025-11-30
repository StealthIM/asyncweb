#include <ctype.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char* strcasestr(const char* haystack, const char* needle) {
    if (!*needle) return (char*)haystack;

    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            h++; n++;
        }
        if (!*n) return (char*)haystack;
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif