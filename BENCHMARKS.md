# asyncweb 性能基线

一组**本地环回**基线数字, 用于发布参照与回归对比。**不是**网络吞吐上限:
所有请求走 127.0.0.1, 测的是库自身开销 (协程调度 + 解析 + syscall), 不含真实
网络的 RTT/带宽。

## 方法

压测程序 `bench/http_bench.c` 是自包含的 —— 用 asyncweb 自己的 HTTP server +
裸 async socket 客户端, 在同一进程/同一 event loop 里跑, 无外部压测工具依赖
(host 上没有 wrk/ab, 且本机 valgrind 与工具链不兼容)。handler 回固定 4 字节
`pong`, 隔离掉业务开销。

两个场景:
- **顺序 (keep-alive)**: 单连接连续发 N 个请求, 无连接重建。量库的最优路径吞吐
  + 每请求延迟分布 (µs 级单调时钟)。
- **并发**: C 条连接各发 M 个请求, 全部并发推进。量 event loop 在多连接交织下
  的吞吐。

计时: 延迟用 `clock_gettime(CLOCK_MONOTONIC)` (µs); 峰值内存用 `/usr/bin/time -v`
的 Maximum RSS。

## 复现

```bash
# 装好 libcoro + asyncweb (openssl 后端) 到某 prefix 后:
cmake -S bench -B bench/build -DCMAKE_PREFIX_PATH=/your/prefix
cmake --build bench/build
/usr/bin/time -v ./bench/build/http_bench            # 默认 20000 / 50x400
./bench/build/http_bench 50000 100 500               # 自定义 seq_n / conns / per
```

## 基线数字

环境: Linux 7.0 / GCC (Release `-O2`) / 明文 HTTP / 环回。取 3 次运行的代表值。

| 场景 | 请求数 | 吞吐 | 延迟 p50 | 延迟 p99 |
|------|--------|------|----------|----------|
| 顺序 keep-alive | 20000 | ~28,700 req/s | 34 µs | ~50 µs |
| 并发 50×400     | 20000 | ~13,800 req/s | — | — |

峰值 RSS (整个进程, 含 server + 客户端 + OpenSSL): **~3.7 MB**。

## 解读

- **顺序 > 并发** 是符合预期的: 环回下顺序 keep-alive 无连接重建、缓存局部性最好;
  并发场景额外付 50 次连接建立 + 协程交织调度。两者都是单线程 loop 的数字。
- **p99 与 p50 接近** (34µs vs ~50µs): 环回下无长尾, 说明协程调度开销稳定、无明显
  抖动或锁竞争。
- **RSS ~3.7MB** 包含 OpenSSL 静态数据; 库自身每连接状态很小 (per-conn buffer 起始
  8KB, 按需翻倍到 64KB 上限)。

这些是**相对基线**: 用于发布后监测回归 (同机器同参数跑, 对比数字是否劣化), 不宜
跨机器/跨场景绝对比较。
