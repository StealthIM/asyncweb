#pragma once

#ifdef __cplusplus
extern "C" {
#endif

char* strcasestr(const char* haystack, const char* needle);

#define with(type, var, manager_name, ...) for(type var = manager_name##_enter(__VA_ARGS__); var!=NULL; manager_name##_exit(var), var=NULL)

#ifdef __cplusplus
}
#endif