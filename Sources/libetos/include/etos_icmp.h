#ifndef ETOS_ICMP_H
#define ETOS_ICMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 默认参数 */
#define ETOS_ICMP_DEFAULT_TIMEOUT_MS 3000
#define ETOS_ICMP_DEFAULT_TTL 64
#define ETOS_ICMP_MAX_PACKET_SIZE 1500

/* ------------------------------------------------------------
   ICMP 结果数据结构（Ping 和 Traceroute 共用）
   ------------------------------------------------------------ */
typedef struct {
  char ip[64];          /* 响应者的 IP 地址 */
  int family;           /* AF_INET 或 AF_INET6，0 表示超时或失败 */
  double rtt_ms;        /* 往返时间（毫秒），超时为 -1 */
  int ttl;              /* 响应包的 TTL/Hop Limit 值 */
  int seq;              /* 序列号 */
  int identifier;       /* ICMP 标识符 */
  bool success;         /* 是否成功收到回复 */
  int error_code;       /* 错误码（0 表示成功，ETIMEDOUT 表示超时） */
  int icmp_type;        /* ICMP 响应类型（0=Echo Reply, 11=Time Exceeded, 3=Dest Unreachable） */
} EtosICMPResult;

/**
 * 执行单次 ICMP Echo（Ping）
 * @param host 目标主机（域名或 IP 地址，支持 IPv4/IPv6）
 * @param timeout_ms 超时时间（毫秒），0 使用默认值 3000ms
 * @param result 输出结果
 * @return 成功返回 0，失败返回 -1
 */
int etos_icmp_echo(const char *host, int timeout_ms, EtosICMPResult *result);

/**
 * 执行单次 Traceroute 跳
 * @param host 目标主机
 * @param ttl 当前跳的 TTL 值（从 1 开始递增）
 * @param timeout_ms 超时时间（毫秒），0 使用默认值 3000ms
 * @param result 输出结果
 * @return 到达目标返回 1，中间跳返回 0，超时或失败返回 -1
 */
int etos_icmp_traceroute_hop(const char *host, int ttl, int timeout_ms, EtosICMPResult *result);

/**
 * 获取 ICMP 错误描述
 * @param error_code 错误码
 * @return 错误描述字符串
 */
const char *etos_icmp_strerror(int error_code);

#ifdef __cplusplus
}
#endif

#endif /* ETOS_ICMP_H */
