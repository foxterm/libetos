#include "etos_traceroute.h"
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
   内部常量
   ------------------------------------------------------------ */
#define TRACEROUTE_PAYLOAD_SIZE 56
#define TRACEROUTE_HEADER_SIZE 8
#define TRACEROUTE_TOTAL_SIZE (TRACEROUTE_HEADER_SIZE + TRACEROUTE_PAYLOAD_SIZE)
#define TRACEROUTE_TIMEOUT_DEFAULT_MS 3000
#define TRACEROUTE_MAX_HOPS_DEFAULT 30

/* ICMP 类型定义（补充标准头文件中可能缺失的） */
#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif

#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif

/* ------------------------------------------------------------
   ICMP 头部结构
   ------------------------------------------------------------ */
typedef struct {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence;
} TracerouteICMPHeader;

/* ------------------------------------------------------------
   内部辅助函数
   ------------------------------------------------------------ */

static uint16_t tr_compute_checksum(const void *data, size_t len) {
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

static double tr_get_time_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static int tr_resolve_host(const char *host, struct sockaddr_storage *addr, int *family) {
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

/** 设置 IPv4 socket 的 TTL */
static int set_ttl_ipv4(int fd, int ttl) {
  return setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

/** 设置 IPv6 socket 的 Hop Limit */
static int set_ttl_ipv6(int fd, int hoplimit) {
  return setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hoplimit, sizeof(hoplimit));
}

/** 执行单跳 traceroute（IPv4） */
static int traceroute_hop_ipv4(int fd, const struct sockaddr_in *dest, int ttl, int seq, int identifier,
                               int timeout_ms, EtosTracerouteHop *hop) {
  memset(hop, 0, sizeof(*hop));
  hop->hop = ttl;
  hop->reached = false;
  hop->rtt_ms = -1;

  /* 设置 TTL */
  if (set_ttl_ipv4(fd, ttl) < 0) {
    hop->error_code = errno;
    return -1;
  }

  /* 构造 ICMP Echo Request */
  uint8_t packet[TRACEROUTE_TOTAL_SIZE];
  memset(packet, 0, sizeof(packet));

  TracerouteICMPHeader *hdr = (TracerouteICMPHeader *)packet;
  hdr->type = ICMP_ECHO;
  hdr->code = 0;
  hdr->checksum = 0;
  hdr->identifier = htons((uint16_t)identifier);
  hdr->sequence = htons((uint16_t)seq);

  /* 填充时间戳 */
  double send_time = tr_get_time_ms();
  uint64_t time_us = (uint64_t)(send_time * 1000.0);
  memcpy(packet + TRACEROUTE_HEADER_SIZE, &time_us, sizeof(time_us));

  hdr->checksum = tr_compute_checksum(packet, sizeof(packet));

  /* 发送 */
  ssize_t sent = sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)dest, sizeof(*dest));
  if (sent < 0) {
    hop->error_code = errno;
    return -1;
  }

  /* 等待响应 */
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  int poll_result = poll(&pfd, 1, timeout_ms);

  if (poll_result <= 0) {
    hop->error_code = (poll_result == 0) ? ETIMEDOUT : errno;
    return -1;
  }

  /* 接收响应 */
  uint8_t recv_buf[1500];
  struct sockaddr_in from;
  socklen_t from_len = sizeof(from);
  ssize_t received = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);

  if (received < TRACEROUTE_HEADER_SIZE) {
    hop->error_code = EMSGSIZE;
    return -1;
  }

  double recv_time = tr_get_time_ms();

  /* 解析响应 */
  TracerouteICMPHeader *reply = (TracerouteICMPHeader *)recv_buf;

  /* 检查是否为 ICMP Time Exceeded 或 Echo Reply */
  if (reply->type == ICMP_TIME_EXCEEDED || reply->type == ICMP_ECHOREPLY) {
    /* 对于 Echo Reply，验证 identifier 和 sequence */
    if (reply->type == ICMP_ECHOREPLY) {
      if (ntohs(reply->identifier) != identifier || ntohs(reply->sequence) != seq) {
        hop->error_code = ESRCH;
        return -1;
      }
    }

    /* 提取 IP 地址 */
    inet_ntop(AF_INET, &from.sin_addr, hop->ip, sizeof(hop->ip));
    hop->family = AF_INET;
    hop->reached = true;

    /* 计算 RTT */
    uint64_t orig_time_us = 0;
    if (received >= (ssize_t)(TRACEROUTE_HEADER_SIZE + sizeof(orig_time_us))) {
      memcpy(&orig_time_us, recv_buf + TRACEROUTE_HEADER_SIZE, sizeof(orig_time_us));
      double orig_time_ms = orig_time_us / 1000.0;
      hop->rtt_ms = recv_time - orig_time_ms;
      if (hop->rtt_ms < 0)
        hop->rtt_ms = 0;
    } else {
      hop->rtt_ms = recv_time - send_time;
    }

    hop->error_code = 0;
    return (reply->type == ICMP_ECHOREPLY) ? 1 : 0; /* 1 = 到达目标，0 = 中间跳 */
  }

  hop->error_code = EPROTONOSUPPORT;
  return -1;
}

/** 执行单跳 traceroute（IPv6） */
static int traceroute_hop_ipv6(int fd, const struct sockaddr_in6 *dest, int ttl, int seq, int identifier,
                               int timeout_ms, EtosTracerouteHop *hop) {
  memset(hop, 0, sizeof(*hop));
  hop->hop = ttl;
  hop->reached = false;
  hop->rtt_ms = -1;

  /* 设置 Hop Limit */
  if (set_ttl_ipv6(fd, ttl) < 0) {
    hop->error_code = errno;
    return -1;
  }

  /* 构造 ICMPv6 Echo Request */
  uint8_t packet[TRACEROUTE_TOTAL_SIZE];
  memset(packet, 0, sizeof(packet));

  struct icmp6_hdr *hdr = (struct icmp6_hdr *)packet;
  hdr->icmp6_type = ICMP6_ECHO_REQUEST;
  hdr->icmp6_code = 0;
  hdr->icmp6_cksum = 0;
  hdr->icmp6_id = htons((uint16_t)identifier);
  hdr->icmp6_seq = htons((uint16_t)seq);

  /* 填充时间戳 */
  double send_time = tr_get_time_ms();
  uint64_t time_us = (uint64_t)(send_time * 1000.0);
  memcpy(packet + sizeof(struct icmp6_hdr), &time_us, sizeof(time_us));

  /* 发送 */
  ssize_t sent = sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)dest, sizeof(*dest));
  if (sent < 0) {
    hop->error_code = errno;
    return -1;
  }

  /* 等待响应 */
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  int poll_result = poll(&pfd, 1, timeout_ms);

  if (poll_result <= 0) {
    hop->error_code = (poll_result == 0) ? ETIMEDOUT : errno;
    return -1;
  }

  /* 接收响应 */
  uint8_t recv_buf[1500];
  struct sockaddr_in6 from;
  socklen_t from_len = sizeof(from);
  ssize_t received = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);

  if (received < (ssize_t)sizeof(struct icmp6_hdr)) {
    hop->error_code = EMSGSIZE;
    return -1;
  }

  double recv_time = tr_get_time_ms();

  /* 解析响应 */
  struct icmp6_hdr *reply = (struct icmp6_hdr *)recv_buf;

  /* 检查是否为 ICMPv6 Time Exceeded 或 Echo Reply */
  if (reply->icmp6_type == ICMP6_TIME_EXCEEDED || reply->icmp6_type == ICMP6_ECHO_REPLY) {
    /* 对于 Echo Reply，验证 */
    if (reply->icmp6_type == ICMP6_ECHO_REPLY) {
      if (ntohs(reply->icmp6_id) != identifier || ntohs(reply->icmp6_seq) != seq) {
        hop->error_code = ESRCH;
        return -1;
      }
    }

    /* 提取 IP 地址 */
    inet_ntop(AF_INET6, &from.sin6_addr, hop->ip, sizeof(hop->ip));
    hop->family = AF_INET6;
    hop->reached = true;

    /* 计算 RTT */
    uint64_t orig_time_us = 0;
    if (received >= (ssize_t)(sizeof(struct icmp6_hdr) + sizeof(orig_time_us))) {
      memcpy(&orig_time_us, recv_buf + sizeof(struct icmp6_hdr), sizeof(orig_time_us));
      double orig_time_ms = orig_time_us / 1000.0;
      hop->rtt_ms = recv_time - orig_time_ms;
      if (hop->rtt_ms < 0)
        hop->rtt_ms = 0;
    } else {
      hop->rtt_ms = recv_time - send_time;
    }

    hop->error_code = 0;
    return (reply->icmp6_type == ICMP6_ECHO_REPLY) ? 1 : 0;
  }

  hop->error_code = EPROTONOSUPPORT;
  return -1;
}

/* ------------------------------------------------------------
   外部接口实现
   ------------------------------------------------------------ */

int etos_traceroute(const char *host, int max_hops, int timeout_ms,
                    EtosTracerouteHop *hops, int *hop_count) {
  if (!host || !hops || !hop_count)
    return -1;

  if (max_hops <= 0)
    max_hops = TRACEROUTE_MAX_HOPS_DEFAULT;
  if (timeout_ms <= 0)
    timeout_ms = TRACEROUTE_TIMEOUT_DEFAULT_MS;

  /* 解析主机 */
  struct sockaddr_storage dest_addr;
  int family;
  if (tr_resolve_host(host, &dest_addr, &family) < 0) {
    *hop_count = 0;
    return -1;
  }

  /* 创建 ICMP socket */
  int protocol = (family == AF_INET6) ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
  int fd = socket(family, SOCK_DGRAM, protocol);
  if (fd < 0) {
    *hop_count = 0;
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
  int count = 0;
  int reached_target = 0;

  for (int ttl = 1; ttl <= max_hops && count < max_hops; ttl++) {
    int ret;
    if (family == AF_INET6) {
      ret = traceroute_hop_ipv6(fd, (struct sockaddr_in6 *)&dest_addr, ttl, ttl, identifier, timeout_ms, &hops[count]);
    } else {
      ret = traceroute_hop_ipv4(fd, (struct sockaddr_in *)&dest_addr, ttl, ttl, identifier, timeout_ms, &hops[count]);
    }

    count++;

    if (ret == 1) {
      /* 到达目标 */
      reached_target = 1;
      break;
    }
  }

  close(fd);
  *hop_count = count;
  return reached_target ? 0 : -1;
}

int etos_traceroute_async(const char *host, int max_hops, int timeout_ms,
                          EtosTracerouteCallback callback, void *context) {
  if (!host || !callback)
    return -1;

  if (max_hops <= 0)
    max_hops = TRACEROUTE_MAX_HOPS_DEFAULT;
  if (timeout_ms <= 0)
    timeout_ms = TRACEROUTE_TIMEOUT_DEFAULT_MS;

  EtosTracerouteHop *hops = (EtosTracerouteHop *)malloc(sizeof(EtosTracerouteHop) * max_hops);
  if (!hops)
    return -1;

  int hop_count = 0;
  int ret = etos_traceroute(host, max_hops, timeout_ms, hops, &hop_count);

  for (int i = 0; i < hop_count; i++) {
    callback(&hops[i], context);
  }

  free(hops);
  return ret;
}

bool etos_traceroute_reached_target(const EtosTracerouteHop *hops, int hop_count, const char *host) {
  if (!hops || hop_count <= 0 || !host)
    return false;

  /* 检查最后一跳是否有响应 */
  const EtosTracerouteHop *last = &hops[hop_count - 1];
  if (!last->reached)
    return false;

  /* 解析目标地址进行比较 */
  struct sockaddr_storage dest_addr;
  int family;
  if (tr_resolve_host(host, &dest_addr, &family) < 0)
    return false;

  char dest_ip[64];
  if (family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *)&dest_addr;
    inet_ntop(AF_INET, &s->sin_addr, dest_ip, sizeof(dest_ip));
  } else {
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&dest_addr;
    inet_ntop(AF_INET6, &s->sin6_addr, dest_ip, sizeof(dest_ip));
  }

  return strcmp(last->ip, dest_ip) == 0;
}
