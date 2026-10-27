#ifndef ETOS_PING_H
#define ETOS_PING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 默认参数 */
#define ETOS_PING_DEFAULT_TIMEOUT_MS 3000
#define ETOS_PING_DEFAULT_TTL 64
#define ETOS_PING_MAX_PACKET_SIZE 1500

/* ------------------------------------------------------------
   Ping 结果数据结构
   ------------------------------------------------------------ */
typedef struct {
  char ip[64];          /* 响应者的 IP 地址 */
  int family;           /* AF_INET 或 AF_INET6 */
  double rtt_ms;        /* 往返时间（毫秒） */
  int ttl;              /* 响应包的 TTL 值 */
  int seq;              /* 序列号 */
  int identifier;       /* ICMP 标识符 */
  bool success;         /* 是否成功收到回复 */
  int error_code;       /* 错误码（0 表示成功） */
} EtosPingResult;

/* ------------------------------------------------------------
   连续 Ping 统计信息
   ------------------------------------------------------------ */
typedef struct {
  int packets_sent;     /* 发送的包数 */
  int packets_received; /* 接收的包数 */
  double min_rtt_ms;    /* 最小 RTT */
  double max_rtt_ms;    /* 最大 RTT */
  double avg_rtt_ms;    /* 平均 RTT */
  double total_time_ms; /* 总耗时 */
} EtosPingStats;

/* ------------------------------------------------------------
   Ping 回调函数类型
   ------------------------------------------------------------ */
typedef void (*EtosPingCallback)(const EtosPingResult *result, void *context);

/**
 * 执行单次 Ping
 * @param host 目标主机（域名或 IP 地址）
 * @param timeout_ms 超时时间（毫秒），0 使用默认值 3000ms
 * @param result 输出结果
 * @return 成功返回 0，失败返回 -1
 */
int etos_ping(const char *host, int timeout_ms, EtosPingResult *result);

/**
 * 执行连续 Ping
 * @param host 目标主机
 * @param count 发送次数，0 表示持续发送直到手动停止
 * @param interval_ms 发送间隔（毫秒），0 使用默认值 1000ms
 * @param timeout_ms 每次 Ping 的超时时间（毫秒），0 使用默认值
 * @param callback 每次收到响应的回调函数
 * @param context 传递给回调的用户数据
 * @param stats 输出统计信息，传 NULL 不收集统计
 * @return 成功返回 0，失败返回 -1
 */
int etos_ping_continuous(const char *host, int count, int interval_ms, int timeout_ms,
                         EtosPingCallback callback, void *context, EtosPingStats *stats);

/**
 * 执行指定次数的 Ping 并返回统计信息（阻塞式）
 * @param host 目标主机
 * @param count 发送次数
 * @param interval_ms 发送间隔（毫秒）
 * @param timeout_ms 超时时间（毫秒）
 * @param stats 输出统计信息
 * @return 成功返回 0，失败返回 -1
 */
int etos_ping_stats(const char *host, int count, int interval_ms, int timeout_ms, EtosPingStats *stats);

/**
 * 获取 Ping 丢包率
 * @param stats Ping 统计信息
 * @return 丢包率（0.0 - 100.0），失败返回 -1.0
 */
double etos_ping_get_loss_rate(const EtosPingStats *stats);

#ifdef __cplusplus
}
#endif

#endif /* ETOS_PING_H */
