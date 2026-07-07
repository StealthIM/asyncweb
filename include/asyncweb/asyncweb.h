#pragma once

/*
 * asyncweb —— 异步 HTTP/HTTPS/WebSocket 库 (公开 API 汇总头)。
 *
 * 用户只需 #include <asyncweb/asyncweb.h>。各子头也可单独 include:
 *   - common.h : 初始化 (anet_init/anet_cleanup) + 结果编解码
 *   - http.h   : HTTP 客户端 (async/sync GET/POST/request)
 *   - http_server.h : 高层 HTTP/HTTPS 服务端
 *   - ws.h     : WebSocket 客户端 + 服务端 (ws/wss)
 *   - socket.h : 低层异步 socket (anet_socket_* / anet_listener_*)
 *   - stream.h : 统一读写流 (anet_stream_*, 明文或 TLS)
 *   - palsock.h: 平台 socket 抽象 (anet_palsock_*) —— 建监听/连接用
 *
 * asyncweb 依赖 libcoro (<libcoro/libcoro.h>) 的协程/事件循环。
 */

#include <asyncweb/common.h>
#include <asyncweb/http.h>
#include <asyncweb/http_server.h>
#include <asyncweb/ws.h>
#include <asyncweb/socket.h>
#include <asyncweb/stream.h>
#include <asyncweb/palsock.h>
