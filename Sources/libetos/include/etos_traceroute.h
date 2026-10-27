#ifndef ETOS_TRACEROUTE_H
#define ETOS_TRACEROUTE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 默认参数 */
#define ETOS_TRACEROUTE_MAX_HOPS 30
#define ETOS_TRACEROUTE_DEFAULT_TIMEOUT_MS 3000
#define ETOS_TRACEROUTE_DEFAULT_PORT 33434

/* ------------------------------------------------------------
   Traceroute 单跳数据结构
   ------------------------------------------------------------ */
typedef struct {
  int hop;              /* 跳数（从 1 开始） */
  char ip[64];          /* 响应者的 IP 地址（超时则为空字符串） */
  int family;           /* AF_INET 或 AF_INET6，0 表示超时 */
  double rtt_ms;        /* 往返时间（毫秒），超时为 -1 */
  bool reached;         /* 是否收到响应 */
  int error_code;       /* 错误码（0 表示成功） */
} EtosTracerouteHop;

/* ------------------------------------------------------------
   Traceroute 回调函数类型
   ------------------------------------------------------------ */
typedef void (*EtosTracerouteCallback)(const EtosTracerouteHop *hop, void *context);

/**
 * 执行 Traceroute（阻塞式）
 * @param host 目标主机（域名或 IP 地址）
 * @param max_hops 最大跳数，0 使用默认值 30
 * @param timeout_ms 每跳超时时间（毫秒），0 使用默认值 3000ms
 * @param hops 输出跳数数组，长度至少为 max_hops
 * @param hop_count 输出实际跳数
 * @return 成功返回 0，失败返回 -1
 */
int etos_traceroute(const char *host, int max_hops, int timeout_ms,
                    EtosTracerouteHop *hops, int *hop_count);

/**
 * 执行 Traceroute（回调式，每收到一跳响应即回调）
 * @param host 目标主机
 * @param max_hops 最大跳数
 * @param timeout_ms 每跳超时时间（毫秒）
 * @param callback 每跳的回调函数
 * @param context 传递给回调的用户数据
 * @return 成功返回 0，失败返回 -1
 */
int etos_traceroute_async(const char *host, int max_hops, int timeout_ms,
                          EtosTracerouteCallback callback, void *context);

/**
 * 检查是否到达目标（用于判断 traceroute 是否完成）
 * @param hops 跳数数组
 * @param hop_count 实际跳数
 * @param host 目标主机（用于比较）
 * @return 到达目标返回 true，否则返回 false
 */
bool etos_traceroute_reached_target(const EtosTracerouteHop *hops, int hop_count, const char *host);

#ifdef __cplusplus
}
#endif

#endif /* ETOS_TRACEROUTE_H */
