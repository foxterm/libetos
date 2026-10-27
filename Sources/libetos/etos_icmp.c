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
   内部常量与结构定义
   ------------------------------------------------------------ */
#define ICMP_PAYLOAD_SIZE 56
#define ICMP_HEADER_SIZE 8
#define ICMP_TOTAL_SIZE (ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE)

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

static int icmp_payload_offset(const uint8_t *buf, ssize_t len, int family) {
  if (len <= 0)
    return 0;
  if (family == AF_INET && (buf[0] >> 4) == 4) {
    int ihl = (buf[0] & 0x0F) * 4;
    return (ihl >= 20 && ihl <= 60) ? ihl : 20;
  }
  if (family == AF_INET6 && (buf[0] >> 4) == 6) {
    return 40;
  }
  return 0;
}

static bool icmp_is_self_echo(const uint8_t *icmp, int family, int identifier, int seq) {
  if (family == AF_INET6) {
    const struct icmp6_hdr *hdr = (const struct icmp6_hdr *)icmp;
    return hdr->icmp6_type == ICMP6_ECHO_REQUEST &&
           ntohs(hdr->icmp6_id) == (uint16_t)identifier &&
           ntohs(hdr->icmp6_seq) == (uint16_t)seq;
  }
  const EtosICMPHeader *hdr = (const EtosICMPHeader *)icmp;
  return hdr->type == ICMP_ECHO &&
         ntohs(hdr->identifier) == (uint16_t)identifier &&
         ntohs(hdr->sequence) == (uint16_t)seq;
}

/* ------------------------------------------------------------
   Ping 实现 (IPv4 / IPv6)
   ------------------------------------------------------------ */

static int icmp_echo_ipv4(int fd, const struct sockaddr_in *dest, int seq, int identifier,
                          int timeout_ms, EtosICMPResult *result) {
  uint8_t packet[ICMP_TOTAL_SIZE];
  memset(packet, 0, sizeof(packet));

  EtosICMPHeader *hdr = (EtosICMPHeader *)packet;
  hdr->type = ICMP_ECHO;
  hdr->code = 0;
  hdr->checksum = 0;
  hdr->identifier = htons((uint16_t)identifier);
  hdr->sequence = htons((uint16_t)seq);

  double send_time = icmp_get_time_ms();
  uint64_t time_us = (uint64_t)(send_time * 1000.0);
  memcpy(packet + ICMP_HEADER_SIZE, &time_us, sizeof(time_us));

  hdr->checksum = icmp_compute_checksum(packet, sizeof(packet));

  ssize_t sent = sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)dest, sizeof(*dest));
  if (sent < 0) {
    result->success = false;
    result->error_code = errno;
    return -1;
  }

  uint8_t recv_buf[ETOS_ICMP_MAX_PACKET_SIZE];
  struct sockaddr_in from;

  for (;;) {
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

    socklen_t from_len = sizeof(from);
    ssize_t received = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);

    if (received < 0) {
      result->success = false;
      result->error_code = errno;
      result->rtt_ms = -1;
      return -1;
    }

    int hdr_offset = icmp_payload_offset(recv_buf, received, AF_INET);
    if (received < hdr_offset + ICMP_HEADER_SIZE) {
      continue;
    }

    double recv_time = icmp_get_time_ms();
    EtosICMPHeader *reply = (EtosICMPHeader *)(recv_buf + hdr_offset);

    if (icmp_is_self_echo((const uint8_t *)reply, AF_INET, identifier, seq)) {
      continue;
    }

    if (reply->type == ICMP_ECHOREPLY || reply->type == ICMP_TIME_EXCEEDED || reply->type == ICMP_DEST_UNREACH) {
      inet_ntop(AF_INET, &from.sin_addr, result->ip, sizeof(result->ip));
      result->family = AF_INET;
      result->success = true;
      result->icmp_type = reply->type;
      result->seq = seq;
      result->identifier = identifier;
      result->error_code = 0;

      if (hdr_offset > 0 && received >= hdr_offset + ICMP_HEADER_SIZE) {
        result->ttl = recv_buf[8];
      }

      result->rtt_ms = recv_time - send_time;
      if (result->rtt_ms < 0) result->rtt_ms = 0;

      return (reply->type == ICMP_ECHOREPLY) ? 1 : 0;
    }
  }
}

static int icmp_echo_ipv6(int fd, const struct sockaddr_in6 *dest, int seq, int identifier,
                          int timeout_ms, EtosICMPResult *result) {
  uint8_t packet[ICMP_TOTAL_SIZE];
  memset(packet, 0, sizeof(packet));

  struct icmp6_hdr *hdr = (struct icmp6_hdr *)packet;
  hdr->icmp6_type = ICMP6_ECHO_REQUEST;
  hdr->icmp6_code = 0;
  hdr->icmp6_cksum = 0;
  hdr->icmp6_id = htons((uint16_t)identifier);
  hdr->icmp6_seq = htons((uint16_t)seq);

  double send_time = icmp_get_time_ms();
  uint64_t time_us = (uint64_t)(send_time * 1000.0);
  memcpy(packet + sizeof(struct icmp6_hdr), &time_us, sizeof(time_us));

  ssize_t sent = sendto(fd, packet, sizeof(packet), 0, (struct sockaddr *)dest, sizeof(*dest));
  if (sent < 0) {
    result->success = false;
    result->error_code = errno;
    return -1;
  }

  uint8_t recv_buf[ETOS_ICMP_MAX_PACKET_SIZE];
  struct sockaddr_in6 from;

  for (;;) {
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

    socklen_t from_len = sizeof(from);
    ssize_t received = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);

    if (received < 0) {
      result->success = false;
      result->error_code = errno;
      result->rtt_ms = -1;
      return -1;
    }

    int hdr_offset = icmp_payload_offset(recv_buf, received, AF_INET6);
    if (received < hdr_offset + (ssize_t)sizeof(struct icmp6_hdr)) {
      continue;
    }

    double recv_time = icmp_get_time_ms();
    struct icmp6_hdr *reply = (struct icmp6_hdr *)(recv_buf + hdr_offset);

    if (icmp_is_self_echo((const uint8_t *)reply, AF_INET6, identifier, seq)) {
      continue;
    }

    if (reply->icmp6_type == ICMP6_ECHO_REPLY || reply->icmp6_type == ICMP6_TIME_EXCEEDED ||
        reply->icmp6_type == ICMP6_DST_UNREACH) {
      inet_ntop(AF_INET6, &from.sin6_addr, result->ip, sizeof(result->ip));
      result->family = AF_INET6;
      result->success = true;
      result->icmp_type = reply->icmp6_type;
      result->seq = seq;
      result->identifier = identifier;
      result->error_code = 0;

      if (hdr_offset > 0 && received >= hdr_offset + (ssize_t)sizeof(struct icmp6_hdr)) {
        result->ttl = recv_buf[7];
      }

      result->rtt_ms = recv_time - send_time;
      if (result->rtt_ms < 0) result->rtt_ms = 0;

      return (reply->icmp6_type == ICMP6_ECHO_REPLY) ? 1 : 0;
    }
  }
}

/* ------------------------------------------------------------
   Traceroute 实现：UDP + connect() 绑定（兼容 macOS/iOS 沙盒及内核事件分发）
   ------------------------------------------------------------ */

static int traceroute_hop_ipv4(const struct sockaddr_in *dest, int ttl, int timeout_ms, EtosICMPResult *result) {
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    result->success = false;
    result->error_code = errno;
    return -1;
  }

#ifdef SO_NOSIGPIPE
  int nosigpipe = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

  /* 沙盒允许修改 UDP 的 TTL */
  if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
    result->success = false;
    result->error_code = errno;
    close(fd);
    return -1;
  }

  struct sockaddr_in target = *dest;
  target.sin_port = htons(33434 + ttl);

  /* 核心：在 macOS/BSD 中，必须 connect UDP 套接字才能捕获异步 ICMP 超时返回 */
  if (connect(fd, (struct sockaddr *)&target, sizeof(target)) < 0) {
    result->success = false;
    result->error_code = errno;
    close(fd);
    return -1;
  }

  double send_time = icmp_get_time_ms();
  char payload = 0;
  ssize_t sent = send(fd, &payload, 1, 0);
  if (sent < 0) {
    result->success = false;
    result->error_code = errno;
    close(fd);
    return -1;
  }

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN | POLLERR;
  int poll_result = poll(&pfd, 1, timeout_ms);

  double recv_time = icmp_get_time_ms();

  if (poll_result <= 0) {
    result->success = false;
    result->error_code = (poll_result == 0) ? ETIMEDOUT : errno;
    result->rtt_ms = -1;
    close(fd);
    return -1;
  }

  struct sockaddr_in from;
  socklen_t from_len = sizeof(from);
  char dummy;
  ssize_t recved = recvfrom(fd, &dummy, 1, 0, (struct sockaddr *)&from, &from_len);
  close(fd);

  result->rtt_ms = recv_time - send_time;
  if (result->rtt_ms < 0) result->rtt_ms = 0;
  result->success = true;
  result->seq = ttl;
  result->error_code = 0;

  /* 判断是中间路由器超时还是到达目标 */
  if (recved < 0 || from.sin_addr.s_addr == 0 || from.sin_addr.s_addr == dest->sin_addr.s_addr) {
    inet_ntop(AF_INET, &dest->sin_addr, result->ip, sizeof(result->ip));
    result->family = AF_INET;
    return 1; // 到达目标
  } else {
    inet_ntop(AF_INET, &from.sin_addr, result->ip, sizeof(result->ip));
    result->family = AF_INET;
    return 0; // 中间跳
  }
}

static int traceroute_hop_ipv6(const struct sockaddr_in6 *dest, int ttl, int timeout_ms, EtosICMPResult *result) {
  int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    result->success = false;
    result->error_code = errno;
    return -1;
  }

#ifdef SO_NOSIGPIPE
  int nosigpipe = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

  if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0) {
    result->success = false;
    result->error_code = errno;
    close(fd);
    return -1;
  }

  struct sockaddr_in6 target = *dest;
  target.sin6_port = htons(33434 + ttl);

  if (connect(fd, (struct sockaddr *)&target, sizeof(target)) < 0) {
    result->success = false;
    result->error_code = errno;
    close(fd);
    return -1;
  }

  double send_time = icmp_get_time_ms();
  char payload = 0;
  ssize_t sent = send(fd, &payload, 1, 0);
  if (sent < 0) {
    result->success = false;
    result->error_code = errno;
    close(fd);
    return -1;
  }

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN | POLLERR;
  int poll_result = poll(&pfd, 1, timeout_ms);

  double recv_time = icmp_get_time_ms();

  if (poll_result <= 0) {
    result->success = false;
    result->error_code = (poll_result == 0) ? ETIMEDOUT : errno;
    result->rtt_ms = -1;
    close(fd);
    return -1;
  }

  struct sockaddr_in6 from;
  socklen_t from_len = sizeof(from);
  char dummy;
  ssize_t recved = recvfrom(fd, &dummy, 1, 0, (struct sockaddr *)&from, &from_len);
  close(fd);

  result->rtt_ms = recv_time - send_time;
  if (result->rtt_ms < 0) result->rtt_ms = 0;
  result->success = true;
  result->seq = ttl;
  result->error_code = 0;

  if (recved < 0 || IN6_ARE_ADDR_EQUAL(&from.sin6_addr, &dest->sin6_addr)) {
    inet_ntop(AF_INET6, &dest->sin6_addr, result->ip, sizeof(result->ip));
    result->family = AF_INET6;
    return 1;
  } else {
    inet_ntop(AF_INET6, &from.sin6_addr, result->ip, sizeof(result->ip));
    result->family = AF_INET6;
    return 0;
  }
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

  struct sockaddr_storage dest_addr;
  int family;
  if (icmp_resolve_host(host, &dest_addr, &family) < 0) {
    result->error_code = EHOSTUNREACH;
    return -1;
  }

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

  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  int identifier = getpid() & 0xFFFF;
  int seq = 1;

  int ret;
  if (family == AF_INET6) {
    ret = icmp_echo_ipv6(fd, (struct sockaddr_in6 *)&dest_addr, seq, identifier, timeout_ms, result);
  } else {
    ret = icmp_echo_ipv4(fd, (struct sockaddr_in *)&dest_addr, seq, identifier, timeout_ms, result);
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

  struct sockaddr_storage dest_addr;
  int family;
  if (icmp_resolve_host(host, &dest_addr, &family) < 0) {
    result->error_code = EHOSTUNREACH;
    return -1;
  }

  if (family == AF_INET6) {
    return traceroute_hop_ipv6((struct sockaddr_in6 *)&dest_addr, ttl, timeout_ms, result);
  } else {
    return traceroute_hop_ipv4((struct sockaddr_in *)&dest_addr, ttl, timeout_ms, result);
  }
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
