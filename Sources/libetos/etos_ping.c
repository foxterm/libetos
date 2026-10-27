#include "etos_ping.h"
#include "etos_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------
   内部常量和宏
   ------------------------------------------------------------ */
#define ICMP_PAYLOAD_SIZE 56
#define ICMP_HEADER_SIZE 8
#define ICMP_TOTAL_SIZE (ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE)

#define PING_INTERVAL_DEFAULT_MS 1000
#define PING_TIMEOUT_DEFAULT_MS 3000

/* ------------------------------------------------------------
   ICMP 头部结构（用于手动构造）
   ------------------------------------------------------------ */
typedef struct {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence;
} ICMPEchoHeader;

/* ------------------------------------------------------------
   内部辅助函数
   ------------------------------------------------------------ */

/** 计算 Internet Checksum (RFC 1071) */
static uint16_t compute_checksum(const void *data, size_t len) {
  const uint16_t *ptr = (const uint16_t *)data;
  uint32_t sum = 0;

  while (len > 1) {
    sum += *ptr++;
    len -= 2;
  }

  if (len == 1) {
    uint16_t last = 0;
    *(uint8_t *)&last = *(const uint8_t *)ptr;
    sum += last;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)~sum;
}

/** 获取当前时间（毫秒） */
static double get_time_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

/** 毫秒级睡眠 */
static void sleep_ms(int ms) {
  if (ms <= 0)
    return;
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

/** 解析主机地址，支持 IPv4/IPv6 */
static int resolve_host(const char *host, struct sockaddr_storage *addr, int *family) {
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  if (getaddrinfo(host, NULL, &hints, &res) != 0) {
    return -1;
  }

  memcpy(addr, res->ai_addr, res->ai_addrlen);
  *family = res->ai_family;
  freeaddrinfo(res);
  return 0;
}

/** 执行单次 ICMP Echo（IPv4） */
static int ping_ipv4(int fd, const struct sockaddr_in *dest, int seq, int identifier, int timeout_ms, EtosPingResult *result) {
  uint8_t packet[ICMP_TOTAL_SIZE];
  memset(packet, 0, sizeof(packet));

  ICMPEchoHeader *hdr = (ICMPEchoHeader *)packet;
  hdr->type = ICMP_ECHO;
  hdr->code = 0;
  hdr->checksum = 0;
  hdr->identifier = htons((uint16_t)identifier);
  hdr->sequence = htons((uint16_t)seq);

  /* 填充时间戳到 payload */
  double send_time = get_time_ms();
  uint64_t time_us = (uint64_t)(send_time * 1000.0);
  memcpy(packet + ICMP_HEADER_SIZE, &time_us, sizeof(time_us));

  /* 计算校验和 */
  hdr->checksum = compute_checksum(packet, sizeof(packet));

  /* 发送 */
  ssize_t sent = sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)dest, sizeof(*dest));
  if (sent < 0) {
    result->success = false;
    result->error_code = errno;
    return -1;
  }

  /* 等待响应 */
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  int poll_result = poll(&pfd, 1, timeout_ms);

  if (poll_result <= 0) {
    result->success = false;
    result->error_code = (poll_result == 0) ? ETIMEDOUT : errno;
    return -1;
  }

  /* 接收响应 */
  uint8_t recv_buf[ETOS_PING_MAX_PACKET_SIZE];
  struct sockaddr_in from;
  socklen_t from_len = sizeof(from);
  ssize_t received = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);

  if (received < ICMP_HEADER_SIZE) {
    result->success = false;
    result->error_code = EMSGSIZE;
    return -1;
  }

  /* 解析 ICMP 响应 */
  ICMPEchoHeader *reply = (ICMPEchoHeader *)recv_buf;
  if (reply->type != ICMP_ECHOREPLY) {
    result->success = false;
    result->error_code = EPROTONOSUPPORT;
    return -1;
  }

  /* 验证 identifier 和 sequence */
  if (ntohs(reply->identifier) != identifier || ntohs(reply->sequence) != seq) {
    result->success = false;
    result->error_code = ESRCH;
    return -1;
  }

  /* 计算 RTT */
  double recv_time = get_time_ms();
  uint64_t orig_time_us = 0;
  if (received >= (ssize_t)(ICMP_HEADER_SIZE + sizeof(orig_time_us))) {
    memcpy(&orig_time_us, recv_buf + ICMP_HEADER_SIZE, sizeof(orig_time_us));
    double orig_time_ms = orig_time_us / 1000.0;
    result->rtt_ms = recv_time - orig_time_ms;
    if (result->rtt_ms < 0)
      result->rtt_ms = 0;
  } else {
    result->rtt_ms = recv_time - send_time;
  }

  /* 填充结果 */
  inet_ntop(AF_INET, &from.sin_addr, result->ip, sizeof(result->ip));
  result->family = AF_INET;
  result->seq = seq;
  result->identifier = identifier;
  result->success = true;
  result->error_code = 0;
  result->ttl = 0; /* TTL 需要 recvmsg + cmsg 获取，此处简化 */

  return 0;
}

/** 执行单次 ICMP Echo（IPv6） */
static int ping_ipv6(int fd, const struct sockaddr_in6 *dest, int seq, int identifier, int timeout_ms, EtosPingResult *result) {
  /* ICMPv6 Echo Request */
  uint8_t packet[ICMP_TOTAL_SIZE];
  memset(packet, 0, sizeof(packet));

  struct icmp6_hdr *hdr = (struct icmp6_hdr *)packet;
  hdr->icmp6_type = ICMP6_ECHO_REQUEST;
  hdr->icmp6_code = 0;
  hdr->icmp6_cksum = 0; /* 内核会自动计算 */
  hdr->icmp6_id = htons((uint16_t)identifier);
  hdr->icmp6_seq = htons((uint16_t)seq);

  /* 填充时间戳 */
  double send_time = get_time_ms();
  uint64_t time_us = (uint64_t)(send_time * 1000.0);
  memcpy(packet + sizeof(struct icmp6_hdr), &time_us, sizeof(time_us));

  /* 发送 */
  ssize_t sent = sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)dest, sizeof(*dest));
  if (sent < 0) {
    result->success = false;
    result->error_code = errno;
    return -1;
  }

  /* 等待响应 */
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  int poll_result = poll(&pfd, 1, timeout_ms);

  if (poll_result <= 0) {
    result->success = false;
    result->error_code = (poll_result == 0) ? ETIMEDOUT : errno;
    return -1;
  }

  /* 接收响应 */
  uint8_t recv_buf[ETOS_PING_MAX_PACKET_SIZE];
  struct sockaddr_in6 from;
  socklen_t from_len = sizeof(from);
  ssize_t received = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);

  if (received < (ssize_t)sizeof(struct icmp6_hdr)) {
    result->success = false;
    result->error_code = EMSGSIZE;
    return -1;
  }

  /* 解析 ICMPv6 响应 */
  struct icmp6_hdr *reply = (struct icmp6_hdr *)recv_buf;
  if (reply->icmp6_type != ICMP6_ECHO_REPLY) {
    result->success = false;
    result->error_code = EPROTONOSUPPORT;
    return -1;
  }

  /* 验证 */
  if (ntohs(reply->icmp6_id) != identifier || ntohs(reply->icmp6_seq) != seq) {
    result->success = false;
    result->error_code = ESRCH;
    return -1;
  }

  /* 计算 RTT */
  double recv_time = get_time_ms();
  uint64_t orig_time_us = 0;
  if (received >= (ssize_t)(sizeof(struct icmp6_hdr) + sizeof(orig_time_us))) {
    memcpy(&orig_time_us, recv_buf + sizeof(struct icmp6_hdr), sizeof(orig_time_us));
    double orig_time_ms = orig_time_us / 1000.0;
    result->rtt_ms = recv_time - orig_time_ms;
    if (result->rtt_ms < 0)
      result->rtt_ms = 0;
  } else {
    result->rtt_ms = recv_time - send_time;
  }

  /* 填充结果 */
  inet_ntop(AF_INET6, &from.sin6_addr, result->ip, sizeof(result->ip));
  result->family = AF_INET6;
  result->seq = seq;
  result->identifier = identifier;
  result->success = true;
  result->error_code = 0;
  result->ttl = 0; /* Hop Limit 需要 recvmsg + cmsg 获取，此处简化 */

  return 0;
}

/* 内部回调收集器结构 */
typedef struct {
  double sum_rtt;
  int received;
} PingCollector;

/* 内部回调函数 */
static void collector_callback(const EtosPingResult *result, void *ctx) {
  PingCollector *c = (PingCollector *)ctx;
  if (result->success) {
    c->sum_rtt += result->rtt_ms;
    c->received++;
  }
}

/* ------------------------------------------------------------
   外部接口实现
   ------------------------------------------------------------ */

int etos_ping(const char *host, int timeout_ms, EtosPingResult *result) {
  if (!host || !result)
    return -1;

  memset(result, 0, sizeof(*result));
  result->success = false;

  if (timeout_ms <= 0)
    timeout_ms = PING_TIMEOUT_DEFAULT_MS;

  /* 解析主机 */
  struct sockaddr_storage dest_addr;
  int family;
  if (resolve_host(host, &dest_addr, &family) < 0) {
    result->error_code = EHOSTUNREACH;
    return -1;
  }

  /* 创建 ICMP socket（使用 SOCK_DGRAM 实现非特权 ICMP） */
  int protocol = (family == AF_INET6) ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
  int fd = socket(family, SOCK_DGRAM, protocol);
  if (fd < 0) {
    result->error_code = errno;
    return -1;
  }

#ifdef SO_NOSIGPIPE
  int nosigpipe = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

  /* 设置接收超时 */
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  int identifier = getpid() & 0xFFFF;
  int seq = 1;

  int ret;
  if (family == AF_INET6) {
    ret = ping_ipv6(fd, (struct sockaddr_in6 *)&dest_addr, seq, identifier, timeout_ms, result);
  } else {
    ret = ping_ipv4(fd, (struct sockaddr_in *)&dest_addr, seq, identifier, timeout_ms, result);
  }

  close(fd);
  return ret;
}

int etos_ping_continuous(const char *host, int count, int interval_ms, int timeout_ms,
                         EtosPingCallback callback, void *context, EtosPingStats *stats) {
  if (!host)
    return -1;

  if (interval_ms <= 0)
    interval_ms = PING_INTERVAL_DEFAULT_MS;
  if (timeout_ms <= 0)
    timeout_ms = PING_TIMEOUT_DEFAULT_MS;

  EtosPingStats local_stats;
  memset(&local_stats, 0, sizeof(local_stats));
  local_stats.min_rtt_ms = 1e9;
  local_stats.max_rtt_ms = 0;

  double start_time = get_time_ms();
  int seq = 0;

  while (count == 0 || seq < count) {
    seq++;
    EtosPingResult result;
    etos_ping(host, timeout_ms, &result);

    if (callback) {
      callback(&result, context);
    }

    local_stats.packets_sent++;
    if (result.success) {
      local_stats.packets_received++;
      if (result.rtt_ms < local_stats.min_rtt_ms)
        local_stats.min_rtt_ms = result.rtt_ms;
      if (result.rtt_ms > local_stats.max_rtt_ms)
        local_stats.max_rtt_ms = result.rtt_ms;
    }

    /* 如果不是最后一次，等待间隔 */
    if (count == 0 || seq < count) {
      sleep_ms(interval_ms);
    }
  }

  double end_time = get_time_ms();
  local_stats.total_time_ms = end_time - start_time;

  if (local_stats.packets_received > 0) {
    local_stats.avg_rtt_ms = (local_stats.min_rtt_ms + local_stats.max_rtt_ms) / 2.0;
  } else {
    local_stats.min_rtt_ms = 0;
  }

  if (stats) {
    *stats = local_stats;
  }

  return 0;
}

int etos_ping_stats(const char *host, int count, int interval_ms, int timeout_ms, EtosPingStats *stats) {
  if (!stats)
    return -1;

  PingCollector collector = {0, 0};
  EtosPingStats local_stats;
  int ret = etos_ping_continuous(host, count, interval_ms, timeout_ms, collector_callback, &collector, &local_stats);

  if (ret == 0 && collector.received > 0) {
    local_stats.avg_rtt_ms = collector.sum_rtt / collector.received;
  }

  *stats = local_stats;
  return ret;
}

double etos_ping_get_loss_rate(const EtosPingStats *stats) {
  if (!stats || stats->packets_sent == 0)
    return -1.0;

  int lost = stats->packets_sent - stats->packets_received;
  return (double)lost / stats->packets_sent * 100.0;
}
