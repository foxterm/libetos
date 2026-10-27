#include "etos_icmp.h"
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
#define ICMP_PAYLOAD_SIZE 56
#define ICMP_HEADER_SIZE 8
#define ICMP_TOTAL_SIZE (ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE)

/* ICMP 类型定义 */
#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
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
} EtosICMPHeader;

/* ------------------------------------------------------------
   内部辅助函数
   ------------------------------------------------------------ */

static uint16_t icmp_compute_checksum(const void *data, size_t len) {
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

static double icmp_get_time_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static int icmp_resolve_host(const char *host, struct sockaddr_storage *addr, int *family) {
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

/** 执行 IPv4 ICMP Echo */
static int icmp_echo_ipv4(int fd, const struct sockaddr_in *dest, int seq, int identifier,
                          int timeout_ms, int ttl, EtosICMPResult *result) {
  uint8_t packet[ICMP_TOTAL_SIZE];
  memset(packet, 0, sizeof(packet));

  EtosICMPHeader *hdr = (EtosICMPHeader *)packet;
  hdr->type = ICMP_ECHO;
  hdr->code = 0;
  hdr->checksum = 0;
  hdr->identifier = htons((uint16_t)identifier);
  hdr->sequence = htons((uint16_t)seq);

  /* 填充时间戳 */
  double send_time = icmp_get_time_ms();
  uint64_t time_us = (uint64_t)(send_time * 1000.0);
  memcpy(packet + ICMP_HEADER_SIZE, &time_us, sizeof(time_us));

  hdr->checksum = icmp_compute_checksum(packet, sizeof(packet));

  /* 设置 TTL（如果指定） */
  if (ttl > 0) {
    set_ttl_ipv4(fd, ttl);
  }

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
    result->rtt_ms = -1;
    return -1;
  }

  /* 接收响应 */
  uint8_t recv_buf[ETOS_ICMP_MAX_PACKET_SIZE];
  struct sockaddr_in from;
  socklen_t from_len = sizeof(from);
  ssize_t received = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);

  if (received < ICMP_HEADER_SIZE) {
    result->success = false;
    result->error_code = EMSGSIZE;
    result->rtt_ms = -1;
    return -1;
  }

  double recv_time = icmp_get_time_ms();

  /* 解析响应 */
  EtosICMPHeader *reply = (EtosICMPHeader *)recv_buf;

  /* 检查是否为 Echo Reply 或 Time Exceeded */
  if (reply->type == ICMP_ECHOREPLY || reply->type == ICMP_TIME_EXCEEDED || reply->type == ICMP_DEST_UNREACH) {
    /* 对于 Echo Reply，验证 identifier 和 sequence */
    if (reply->type == ICMP_ECHOREPLY) {
      if (ntohs(reply->identifier) != identifier || ntohs(reply->sequence) != seq) {
        result->success = false;
        result->error_code = ESRCH;
        result->rtt_ms = -1;
        return -1;
      }
    }

    /* 提取 IP 地址 */
    inet_ntop(AF_INET, &from.sin_addr, result->ip, sizeof(result->ip));
    result->family = AF_INET;
    result->success = true;
    result->icmp_type = reply->type;
    result->seq = seq;
    result->identifier = identifier;
    result->error_code = 0;

    /* 计算 RTT */
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

    return (reply->type == ICMP_ECHOREPLY) ? 1 : 0;
  }

  result->success = false;
  result->error_code = EPROTONOSUPPORT;
  result->rtt_ms = -1;
  return -1;
}

/** 执行 IPv6 ICMP Echo */
static int icmp_echo_ipv6(int fd, const struct sockaddr_in6 *dest, int seq, int identifier,
                          int timeout_ms, int ttl, EtosICMPResult *result) {
  uint8_t packet[ICMP_TOTAL_SIZE];
  memset(packet, 0, sizeof(packet));

  struct icmp6_hdr *hdr = (struct icmp6_hdr *)packet;
  hdr->icmp6_type = ICMP6_ECHO_REQUEST;
  hdr->icmp6_code = 0;
  hdr->icmp6_cksum = 0;
  hdr->icmp6_id = htons((uint16_t)identifier);
  hdr->icmp6_seq = htons((uint16_t)seq);

  /* 填充时间戳 */
  double send_time = icmp_get_time_ms();
  uint64_t time_us = (uint64_t)(send_time * 1000.0);
  memcpy(packet + sizeof(struct icmp6_hdr), &time_us, sizeof(time_us));

  /* 设置 Hop Limit（如果指定） */
  if (ttl > 0) {
    set_ttl_ipv6(fd, ttl);
  }

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
    result->rtt_ms = -1;
    return -1;
  }

  /* 接收响应 */
  uint8_t recv_buf[ETOS_ICMP_MAX_PACKET_SIZE];
  struct sockaddr_in6 from;
  socklen_t from_len = sizeof(from);
  ssize_t received = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);

  if (received < (ssize_t)sizeof(struct icmp6_hdr)) {
    result->success = false;
    result->error_code = EMSGSIZE;
    result->rtt_ms = -1;
    return -1;
  }

  double recv_time = icmp_get_time_ms();

  /* 解析响应 */
  struct icmp6_hdr *reply = (struct icmp6_hdr *)recv_buf;

  /* 检查是否为 Echo Reply 或 Time Exceeded */
  if (reply->icmp6_type == ICMP6_ECHO_REPLY || reply->icmp6_type == ICMP6_TIME_EXCEEDED ||
      reply->icmp6_type == ICMP6_DST_UNREACH) {
    /* 对于 Echo Reply，验证 */
    if (reply->icmp6_type == ICMP6_ECHO_REPLY) {
      if (ntohs(reply->icmp6_id) != identifier || ntohs(reply->icmp6_seq) != seq) {
        result->success = false;
        result->error_code = ESRCH;
        result->rtt_ms = -1;
        return -1;
      }
    }

    /* 提取 IP 地址 */
    inet_ntop(AF_INET6, &from.sin6_addr, result->ip, sizeof(result->ip));
    result->family = AF_INET6;
    result->success = true;
    result->icmp_type = reply->icmp6_type;
    result->seq = seq;
    result->identifier = identifier;
    result->error_code = 0;

    /* 计算 RTT */
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

    return (reply->icmp6_type == ICMP6_ECHO_REPLY) ? 1 : 0;
  }

  result->success = false;
  result->error_code = EPROTONOSUPPORT;
  result->rtt_ms = -1;
  return -1;
}

/* ------------------------------------------------------------
   外部接口实现
   ------------------------------------------------------------ */

int etos_icmp_echo(const char *host, int timeout_ms, EtosICMPResult *result) {
  if (!host || !result)
    return -1;

  memset(result, 0, sizeof(*result));
  result->success = false;
  result->rtt_ms = -1;

  if (timeout_ms <= 0)
    timeout_ms = ETOS_ICMP_DEFAULT_TIMEOUT_MS;

  /* 解析主机 */
  struct sockaddr_storage dest_addr;
  int family;
  if (icmp_resolve_host(host, &dest_addr, &family) < 0) {
    result->error_code = EHOSTUNREACH;
    return -1;
  }

  /* 创建 ICMP socket */
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
    ret = icmp_echo_ipv6(fd, (struct sockaddr_in6 *)&dest_addr, seq, identifier, timeout_ms, 0, result);
  } else {
    ret = icmp_echo_ipv4(fd, (struct sockaddr_in *)&dest_addr, seq, identifier, timeout_ms, 0, result);
  }

  close(fd);
  return ret;
}

int etos_icmp_traceroute_hop(const char *host, int ttl, int timeout_ms, EtosICMPResult *result) {
  if (!host || !result || ttl <= 0)
    return -1;

  memset(result, 0, sizeof(*result));
  result->success = false;
  result->rtt_ms = -1;

  if (timeout_ms <= 0)
    timeout_ms = ETOS_ICMP_DEFAULT_TIMEOUT_MS;

  /* 解析主机 */
  struct sockaddr_storage dest_addr;
  int family;
  if (icmp_resolve_host(host, &dest_addr, &family) < 0) {
    result->error_code = EHOSTUNREACH;
    return -1;
  }

  /* 创建 ICMP socket */
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
  int seq = ttl; /* 使用 TTL 作为序列号，便于追踪 */

  int ret;
  if (family == AF_INET6) {
    ret = icmp_echo_ipv6(fd, (struct sockaddr_in6 *)&dest_addr, seq, identifier, timeout_ms, ttl, result);
  } else {
    ret = icmp_echo_ipv4(fd, (struct sockaddr_in *)&dest_addr, seq, identifier, timeout_ms, ttl, result);
  }

  close(fd);
  return ret; /* 1 = 到达目标，0 = 中间跳，-1 = 超时或失败 */
}

const char *etos_icmp_strerror(int error_code) {
  switch (error_code) {
    case 0:
      return "Success";
    case ETIMEDOUT:
      return "Request timed out";
    case EHOSTUNREACH:
      return "Host unreachable";
    case ENETUNREACH:
      return "Network unreachable";
    case ECONNREFUSED:
      return "Connection refused";
    case EMSGSIZE:
      return "Message too long";
    case EPROTONOSUPPORT:
      return "Protocol not supported";
    case ESRCH:
      return "No matching response found";
    default:
      return strerror(error_code);
  }
}
