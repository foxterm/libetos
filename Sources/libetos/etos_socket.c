#include "etos_socket.h"
#include "etos_base64.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <io.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

typedef int socklen_t;
#define strncasecmp _strnicmp
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ETOS_INVALID_SOCKET
#if defined(_WIN32)
#define ETOS_INVALID_SOCKET (SOCKET)(~0)
#else
#define ETOS_INVALID_SOCKET (-1)
#endif
#endif

/* ------------------------------------------------------------
   网络环境初始化 / 清理接口
   ------------------------------------------------------------ */
int etos_socket_init_env(void) {
#if defined(_WIN32)
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    return -1;
  }
#endif
  return 0;
}

void etos_socket_cleanup_env(void) {
#if defined(_WIN32)
  WSACleanup();
#endif
}

/* ------------------------------------------------------------
   内部辅助函数
   ------------------------------------------------------------ */
static void etos_clean_host(const char *src, char *dst, size_t dst_len) {
  if (!src || !dst || dst_len == 0)
    return;

  size_t len = strlen(src);
  if (src[0] == '[' && len > 1 && src[len - 1] == ']' && len < dst_len + 2) {
    strncpy(dst, src + 1, len - 2);
    dst[len - 2] = '\0';
  } else {
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
  }
}

static void set_nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
  int optval = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const char *)&optval, sizeof(optval));
#else
  (void)fd;
#endif
}

/**
 * 绑定 Socket 到指定的网络接口 (支持网卡名如 "en0" 或本地 IP)
 */
static int bind_to_interface(int fd, int family, const char *ifname_or_ip) {
  if (!ifname_or_ip || ifname_or_ip[0] == '\0') {
    return 0;
  }

  // 1. 尝试作为网卡接口名处理(如 "en0", "en1")
#if defined(IP_BOUND_IF) || defined(IPV6_BOUND_IF)
  unsigned int ifindex = if_nametoindex(ifname_or_ip);
  if (ifindex != 0) {
#if defined(IP_BOUND_IF)
    if (family == AF_INET) {
      return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex));
    }
#endif
#if defined(IPV6_BOUND_IF)
    if (family == AF_INET6) {
      return setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &ifindex, sizeof(ifindex));
    }
#endif
    return -1;
  }
#endif

  // 2. 若非网卡名，尝试解析为本地 IP 地址并调用 bind
  if (family == AF_INET) {
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ifname_or_ip, &local_addr.sin_addr) == 1) {
      return bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    }
  } else if (family == AF_INET6) {
    struct sockaddr_in6 local_addr6;
    memset(&local_addr6, 0, sizeof(local_addr6));
    local_addr6.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, ifname_or_ip, &local_addr6.sin6_addr) == 1) {
      return bind(fd, (struct sockaddr *)&local_addr6, sizeof(local_addr6));
    }
  }

  return -1;
}

static bool recv_exact(int fd, void *buf, size_t len, int timeout_ms) {
  size_t total_read = 0;
  char *ptr = (char *)buf;

  while (total_read < len) {
    ssize_t rc = etos_socket_recv_timeout(fd, ptr + total_read, len - total_read, 0, timeout_ms);
    if (rc <= 0) {
      return false;
    }
    total_read += rc;
  }
  return true;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
  if (timeout_ms <= 0) {
    return connect(fd, addr, addrlen);
  }

  if (etos_socket_set_blocking(fd, false) != 0) {
    return -1;
  }

  int ret = connect(fd, addr, addrlen);
#if defined(_WIN32)
  if (ret < 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
    etos_socket_set_blocking(fd, true);
    return -1;
  }
#else
  if (ret < 0 && errno != EINPROGRESS) {
    etos_socket_set_blocking(fd, true);
    return -1;
  }
#endif

  if (ret == 0) {
    etos_socket_set_blocking(fd, true);
    return 0;
  }

#if defined(_WIN32)
  struct pollfd pfd;
  pfd.fd = (SOCKET)fd;
  pfd.events = POLLOUT | POLLIN;
  pfd.revents = 0;

  ret = WSAPoll(&pfd, 1, timeout_ms);
#else
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLOUT | POLLIN;
  pfd.revents = 0;

  ret = poll(&pfd, 1, timeout_ms);
#endif

  if (ret <= 0) {
    etos_socket_set_blocking(fd, true);
    return -1;
  }

  int error = 0;
  socklen_t len = (socklen_t)sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0 || error != 0) {
#if !defined(_WIN32)
    if (error != 0)
      errno = error;
#endif
    etos_socket_set_blocking(fd, true);
    return -1;
  }

  etos_socket_set_blocking(fd, true);
  return 0;
}

static int extract_sockaddr_info(const struct sockaddr_storage *addr, char *ip_buf, size_t ip_buf_len, int *port) {
  socklen_t buf_len = (socklen_t)ip_buf_len;
  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *)addr;
    *port = ntohs(s->sin_port);
    if (inet_ntop(AF_INET, &s->sin_addr, ip_buf, buf_len) == NULL) {
      return -1;
    }
  } else if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;
    *port = ntohs(s->sin6_port);
    if (inet_ntop(AF_INET6, &s->sin6_addr, ip_buf, buf_len) == NULL) {
      return -1;
    }
  } else {
    return -1;
  }
  return 0;
}

static bool handshake_http_proxy(int fd, const char *target_host, int target_port, const char *user, const char *password, int timeout_ms) {
  if (!target_host || target_port <= 0 || target_port > 65535) {
    return false;
  }

  char req[1024];
  int len = 0;

  char auth_header[512] = "";
  if (user && password && user[0] != '\0') {
    char auth_raw[256];
    snprintf(auth_raw, sizeof(auth_raw), "%s:%s", user, password);
    char *auth_b64 = etos_base64_encode(auth_raw);
    if (auth_b64) {
      snprintf(auth_header, sizeof(auth_header), "Proxy-Authorization: Basic %s\r\n", auth_b64);
      etos_base64_free(auth_b64);
    }
  }

  struct in6_addr dummy_v6;
  if (inet_pton(AF_INET6, target_host, &dummy_v6) == 1) {
    len = snprintf(req, sizeof(req),
                   "CONNECT [%s]:%d HTTP/1.1\r\n"
                   "Host: [%s]:%d\r\n"
                   "%s\r\n",
                   target_host, target_port, target_host, target_port, auth_header);
  } else {
    len = snprintf(req, sizeof(req),
                   "CONNECT %s:%d HTTP/1.1\r\n"
                   "Host: %s:%d\r\n"
                   "%s\r\n",
                   target_host, target_port, target_host, target_port, auth_header);
  }

  if (len < 0 || len >= (int)sizeof(req) || etos_socket_send_timeout(fd, req, (size_t)len, 0, timeout_ms) <= 0) {
    return false;
  }

  char resp[2048];
  size_t resp_len = 0;
  bool header_complete = false;

  while (resp_len < sizeof(resp) - 1) {
    ssize_t rc = etos_socket_recv_timeout(fd, resp + resp_len, sizeof(resp) - 1 - resp_len, 0, timeout_ms);
    if (rc <= 0)
      break;
    resp_len += (size_t)rc;
    resp[resp_len] = '\0';

    if (strstr(resp, "\r\n\r\n") != NULL) {
      header_complete = true;
      break;
    }
  }

  if (!header_complete) {
    return false;
  }

  if (strncasecmp(resp, "HTTP/1.0 200", 12) == 0 || strncasecmp(resp, "HTTP/1.1 200", 12) == 0) {
    return true;
  }

  return false;
}

static bool handshake_socks5_proxy(int fd, const char *target_host, int target_port, const char *user, const char *password, int timeout_ms) {
  if (!target_host || target_port <= 0 || target_port > 65535) {
    return false;
  }

  unsigned char auth_req[3];
  auth_req[0] = 0x05;
  auth_req[1] = 0x01;
  auth_req[2] = (user && password && user[0] != '\0') ? 0x02 : 0x00;

  if (etos_socket_send_timeout(fd, (char *)auth_req, 3, 0, timeout_ms) <= 0) {
    return false;
  }

  unsigned char auth_resp[2] = {0};
  if (!recv_exact(fd, auth_resp, 2, timeout_ms) || auth_resp[0] != 0x05) {
    return false;
  }

  if (auth_resp[1] == 0x02) {
    if (!user || !password)
      return false;

    size_t ulen = strlen(user);
    size_t plen = strlen(password);
    if (ulen > 255 || plen > 255)
      return false;

    unsigned char pass_req[512];
    size_t pass_len = 0;
    pass_req[pass_len++] = 0x01;
    pass_req[pass_len++] = (unsigned char)ulen;
    memcpy(&pass_req[pass_len], user, ulen);
    pass_len += ulen;
    pass_req[pass_len++] = (unsigned char)plen;
    memcpy(&pass_req[pass_len], password, plen);
    pass_len += plen;

    if (etos_socket_send_timeout(fd, (char *)pass_req, pass_len, 0, timeout_ms) <= 0) {
      return false;
    }

    unsigned char pass_resp[2] = {0};
    if (!recv_exact(fd, pass_resp, 2, timeout_ms) || pass_resp[1] != 0x00) {
      return false;
    }
  } else if (auth_resp[1] != 0x00) {
    return false;
  }

  unsigned char conn_req[300];
  size_t p = 0;

  conn_req[p++] = 0x05;
  conn_req[p++] = 0x01;
  conn_req[p++] = 0x00;

  struct in_addr addr4;
  struct in6_addr addr6;

  if (inet_pton(AF_INET, target_host, &addr4) == 1) {
    conn_req[p++] = 0x01;
    memcpy(&conn_req[p], &addr4, 4);
    p += 4;
  } else if (inet_pton(AF_INET6, target_host, &addr6) == 1) {
    conn_req[p++] = 0x04;
    memcpy(&conn_req[p], &addr6, 16);
    p += 16;
  } else {
    size_t target_len = strlen(target_host);
    if (target_len > 255)
      return false;
    conn_req[p++] = 0x03;
    conn_req[p++] = (unsigned char)target_len;
    memcpy(&conn_req[p], target_host, target_len);
    p += target_len;
  }

  unsigned short net_port = htons((unsigned short)target_port);
  memcpy(&conn_req[p], &net_port, 2);
  p += 2;

  if (etos_socket_send_timeout(fd, (char *)conn_req, p, 0, timeout_ms) <= 0) {
    return false;
  }

  unsigned char head[4];
  if (!recv_exact(fd, head, 4, timeout_ms)) {
    return false;
  }

  if (head[0] != 0x05 || head[1] != 0x00) {
    return false;
  }

  size_t skip_bytes = 0;
  if (head[3] == 0x01) {
    skip_bytes = 4 + 2;
  } else if (head[3] == 0x04) {
    skip_bytes = 16 + 2;
  } else if (head[3] == 0x03) {
    unsigned char dlen = 0;
    if (!recv_exact(fd, &dlen, 1, timeout_ms))
      return false;
    skip_bytes = (size_t)dlen + 2;
  } else {
    return false;
  }

  unsigned char dummy[260];
  if (!recv_exact(fd, dummy, skip_bytes, timeout_ms)) {
    return false;
  }

  return true;
}

static bool is_ignored_interface(const char *name) {
  if (!name)
    return true;

  // 常见的虚拟/系统内置接口前缀，在实际选网卡场景下无需暴露给用户
  const char *ignore_prefixes[] = {
      "lo",     // Loopback
      "utun",   // VPN / Network Extension
      "awdl",   // Apple Wireless Direct Link (AirDrop/HandOff)
      "llw",    // Low Latency WLAN
      "ap",     // Apple Access Point
      "bridge", // Bridge Interface
      "gif",    // Generic Tunnel Interface
      "stf",    // 6to4 Tunneling
      "p2p",    // Peer-to-Peer
      "vnic"    // Virtual Network Interface
  };

  size_t count = sizeof(ignore_prefixes) / sizeof(ignore_prefixes[0]);
  for (size_t i = 0; i < count; i++) {
    size_t len = strlen(ignore_prefixes[i]);
    if (strncmp(name, ignore_prefixes[i], len) == 0) {
      return true; // 命中黑名单，跳过
    }
  }

  return false;
}

/* ------------------------------------------------------------
   外部接口实现
   ------------------------------------------------------------ */
EtosInterfaceInfo *etos_socket_get_interface_infos(int *count) {
  if (!count)
    return NULL;
  *count = 0;

#if defined(_WIN32)
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
  ULONG outBufLen = 15000;
  PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
  if (!pAddresses)
    return NULL;

  if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen) != ERROR_SUCCESS) {
    free(pAddresses);
    return NULL;
  }

  int capacity = 8, total = 0;
  EtosInterfaceInfo *list = (EtosInterfaceInfo *)malloc(sizeof(EtosInterfaceInfo) * capacity);

  for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != NULL; pCurr = pCurr->Next) {
    if (pCurr->OperStatus != IfOperStatusUp || pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
      continue;

    for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress; pUnicast != NULL; pUnicast = pUnicast->Next) {
      char ip_str[64] = {0};
      int family = pUnicast->Address.lpSockaddr->sa_family;
      if (family == AF_INET) {
        inet_ntop(AF_INET, &(((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr), ip_str, sizeof(ip_str));
      } else if (family == AF_INET6) {
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)pUnicast->Address.lpSockaddr)->sin6_addr), ip_str, sizeof(ip_str));
      } else {
        continue;
      }

      if (total >= capacity) {
        capacity *= 2;
        list = (EtosInterfaceInfo *)realloc(list, sizeof(EtosInterfaceInfo) * capacity);
      }

      wcstombs(list[total].ifname, pCurr->FriendlyName, sizeof(list[total].ifname) - 1);
      strncpy(list[total].ip, ip_str, sizeof(list[total].ip) - 1);
      total++;
      break;
    }
  }

  free(pAddresses);
  *count = total;
  return list;

#else
  // 100% 保持原版的获取网卡逻辑
  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs(&ifaddr) == -1) {
    return NULL;
  }

  int capacity = 8;
  EtosInterfaceInfo *list = (EtosInterfaceInfo *)malloc(sizeof(EtosInterfaceInfo) * capacity);
  if (!list) {
    freeifaddrs(ifaddr);
    return NULL;
  }

  int total = 0;
  for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name || !ifa->ifa_addr)
      continue;

    // 1. 过滤状态未启用 (IFF_UP) 或 环回卡 (IFF_LOOPBACK)
    unsigned int flags = ifa->ifa_flags;
    if ((flags & IFF_UP) == 0 || (flags & IFF_LOOPBACK) != 0)
      continue;

    // 2. 过滤虚拟/内部网卡 (如 utun, awdl, llw 等)
    if (is_ignored_interface(ifa->ifa_name))
      continue;

    int family = ifa->ifa_addr->sa_family;
    if (family != AF_INET && family != AF_INET6)
      continue;

    // 3. 解析 IP 地址
    char ip_str[INET6_ADDRSTRLEN] = {0};
    if (family == AF_INET) {
      inet_ntop(AF_INET, &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr), ip_str, sizeof(ip_str));
    } else {
      inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr), ip_str, sizeof(ip_str));
    }

    if (ip_str[0] == '\0')
      continue;

    // 去除 IPv6 Zone ID
    char *percent = strchr(ip_str, '%');
    if (percent)
      *percent = '\0';

    // 4. 按网卡名称强行去重
    int existing_idx = -1;
    for (int i = 0; i < total; i++) {
      if (strcmp(list[i].ifname, ifa->ifa_name) == 0) {
        existing_idx = i;
        break;
      }
    }

    if (existing_idx != -1) {
      // 优先显示 IPv4 地址
      if (family == AF_INET) {
        strncpy(list[existing_idx].ip, ip_str, sizeof(list[existing_idx].ip) - 1);
        list[existing_idx].ip[sizeof(list[existing_idx].ip) - 1] = '\0';
      }
    } else {
      if (total >= capacity) {
        capacity *= 2;
        EtosInterfaceInfo *new_list = (EtosInterfaceInfo *)realloc(list, sizeof(EtosInterfaceInfo) * capacity);
        if (!new_list) {
          free(list);
          freeifaddrs(ifaddr);
          return NULL;
        }
        list = new_list;
      }

      strncpy(list[total].ifname, ifa->ifa_name, sizeof(list[total].ifname) - 1);
      list[total].ifname[sizeof(list[total].ifname) - 1] = '\0';

      strncpy(list[total].ip, ip_str, sizeof(list[total].ip) - 1);
      list[total].ip[sizeof(list[total].ip) - 1] = '\0';

      total++;
    }
  }

  freeifaddrs(ifaddr);
  *count = total;
  return list;
#endif
}

void etos_socket_free_interface_infos(EtosInterfaceInfo *infos) {
  if (infos) {
    free(infos);
  }
}

int etos_socket_resolve_all_ips(const char *host, EtosIPAddr *addrs, size_t max_addrs) {
  if (!host || !addrs || max_addrs == 0) {
    return -1;
  }

  char clean_host[256];
  etos_clean_host(host, clean_host, sizeof(clean_host));

  struct addrinfo hints, *res = NULL, *rp = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(clean_host, NULL, &hints, &res) != 0) {
    return -1;
  }

  size_t count = 0;
  for (rp = res; rp != NULL && count < max_addrs; rp = rp->ai_next) {
    char ip_str[INET6_ADDRSTRLEN] = {0};
    void *addr_ptr = NULL;

    if (rp->ai_family == AF_INET) {
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
      addr_ptr = &(ipv4->sin_addr);
    } else if (rp->ai_family == AF_INET6) {
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
      addr_ptr = &(ipv6->sin6_addr);
    } else {
      continue;
    }

    if (inet_ntop(rp->ai_family, addr_ptr, ip_str, (socklen_t)sizeof(ip_str)) == NULL) {
      continue;
    }

    bool duplicate = false;
    for (size_t i = 0; i < count; i++) {
      if (strcmp(addrs[i].ip, ip_str) == 0) {
        duplicate = true;
        break;
      }
    }

    if (!duplicate) {
      strncpy(addrs[count].ip, ip_str, sizeof(addrs[count].ip) - 1);
      addrs[count].ip[sizeof(addrs[count].ip) - 1] = '\0';
      addrs[count].family = rp->ai_family;
      count++;
    }
  }

  freeaddrinfo(res);
  return (int)count;
}

int etos_socket_set_keepalive(int fd, bool enable, int idle_sec, int interval_sec, int count) {
  int optval = enable ? 1 : 0;
  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&optval, sizeof(optval)) < 0) {
    return -1;
  }

  if (enable) {
#if defined(TCP_KEEPALIVE)
    if (idle_sec > 0) {
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, (const char *)&idle_sec, sizeof(idle_sec));
    }
#elif defined(TCP_KEEPIDLE)
    if (idle_sec > 0) {
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (const char *)&idle_sec, sizeof(idle_sec));
    }
#endif

#if defined(TCP_KEEPINTVL)
    if (interval_sec > 0) {
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (const char *)&interval_sec, sizeof(interval_sec));
    }
#endif

#if defined(TCP_KEEPCNT)
    if (count > 0) {
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (const char *)&count, sizeof(count));
    }
#endif
  }
  return 0;
}

int etos_socket_set_nodelay(int fd, bool enable) {
  int optval = enable ? 1 : 0;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&optval, sizeof(optval));
}

int etos_socket_connect(const char *host, int port, int timeout_ms, const char *ifname_or_ip) {
  if (!host || port <= 0 || port > 65535)
    return ETOS_INVALID_SOCKET;

  char clean_host[256];
  etos_clean_host(host, clean_host, sizeof(clean_host));

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  struct addrinfo hints, *res = NULL, *rp = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG | AI_CANONNAME;
  hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo(clean_host, port_str, &hints, &res) != 0) {
    return ETOS_INVALID_SOCKET;
  }

  int fd = ETOS_INVALID_SOCKET;
  for (rp = res; rp != NULL; rp = rp->ai_next) {
    fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0)
      continue;

    set_nosigpipe(fd);

    /* 若指定了网卡参数，在 connect 前完成绑定 */
    if (ifname_or_ip && bind_to_interface(fd, rp->ai_family, ifname_or_ip) < 0) {
      etos_socket_close(fd);
      fd = ETOS_INVALID_SOCKET;
      continue;
    }

    if (connect_with_timeout(fd, rp->ai_addr, rp->ai_addrlen, timeout_ms) == 0) {
      break;
    }

    etos_socket_close(fd);
    fd = ETOS_INVALID_SOCKET;
  }

  if (res) {
    freeaddrinfo(res);
  }

  if (fd != ETOS_INVALID_SOCKET) {
    etos_socket_set_nodelay(fd, true);
    etos_socket_set_keepalive(fd, true, 5, 5, 10);
  }

  return fd;
}

int etos_socket_connect_proxy(int type, const char *proxy_host, int proxy_port, int timeout_ms, const char *target_host, int target_port, const char *user, const char *password, const char *ifname_or_ip) {
  if (type == ETOS_PROXY_NONE) {
    return etos_socket_connect(target_host, target_port, timeout_ms, ifname_or_ip);
  }

  int fd = etos_socket_connect(proxy_host, proxy_port, timeout_ms, ifname_or_ip);
  if (fd < 0)
    return ETOS_INVALID_SOCKET;

  bool ok = false;
  if (type == ETOS_PROXY_HTTP) {
    ok = handshake_http_proxy(fd, target_host, target_port, user, password, timeout_ms);
  } else if (type == ETOS_PROXY_SOCKS5) {
    ok = handshake_socks5_proxy(fd, target_host, target_port, user, password, timeout_ms);
  }

  if (!ok) {
    etos_socket_close(fd);
    return ETOS_INVALID_SOCKET;
  }

  return fd;
}

ssize_t etos_socket_send_timeout(int fd, const char *buf, size_t len, int flags, int timeout_ms) {
  if (timeout_ms > 0) {
#if defined(_WIN32)
    struct pollfd pfd;
    pfd.fd = (SOCKET)fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int ret = WSAPoll(&pfd, 1, timeout_ms);
#else
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int ret = poll(&pfd, 1, timeout_ms);
#endif
    if (ret <= 0)
      return -ETIMEDOUT;
  }
  return etos_socket_send(fd, buf, len, flags);
}

ssize_t etos_socket_recv_timeout(int fd, char *buf, size_t len, int flags, int timeout_ms) {
  if (timeout_ms > 0) {
#if defined(_WIN32)
    struct pollfd pfd;
    pfd.fd = (SOCKET)fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int ret = WSAPoll(&pfd, 1, timeout_ms);
#else
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int ret = poll(&pfd, 1, timeout_ms);
#endif
    if (ret <= 0)
      return -ETIMEDOUT;
  }
  return etos_socket_recv(fd, buf, len, flags);
}

ssize_t etos_socket_send(int fd, const char *buf, size_t len, int flags) {
  return send(fd, buf, (int)len, flags);
}

ssize_t etos_socket_recv(int fd, char *buf, size_t len, int flags) {
  return recv(fd, buf, (int)len, flags);
}

int etos_socket_shutdown(int fd, int how) { return shutdown(fd, how); }

void etos_socket_close(int fd) {
  if (fd >= 0) {
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
  }
}

int etos_socket_set_blocking(int fd, bool blocking) {
#if defined(_WIN32)
  u_long mode = blocking ? 0 : 1;
  return ioctlsocket(fd, FIONBIO, &mode);
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    return -1;

  if (blocking) {
    flags &= ~O_NONBLOCK;
  } else {
    flags |= O_NONBLOCK;
  }
  return fcntl(fd, F_SETFL, flags);
#endif
}

bool etos_socket_is_connect(int fd) {
  if (fd < 0)
    return false;

  char buf;
#if defined(_WIN32)
  ssize_t res = recv(fd, &buf, 1, MSG_PEEK);
  if (res == 0) {
    return false;
  }
  if (res < 0) {
    if (WSAGetLastError() == WSAEWOULDBLOCK) {
      return true;
    }
    return false;
  }
#else
  ssize_t res = recv(fd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
  if (res == 0) {
    return false;
  }
  if (res < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return true;
    }
    return false;
  }
#endif
  return true;
}

int etos_socket_last_error(void) {
#if defined(_WIN32)
  return WSAGetLastError();
#else
  return errno;
#endif
}

const char *etos_socket_strerror(int errnum) { return strerror(errnum); }

int etos_socket_get_peer_info(int fd, char *ip_buf, size_t ip_buf_len, int *port) {
  if (fd < 0 || !ip_buf || ip_buf_len == 0 || !port) {
    return -1;
  }

  struct sockaddr_storage addr;
  socklen_t addr_len = (socklen_t)sizeof(addr);

  if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) < 0) {
    return -1;
  }

  return extract_sockaddr_info(&addr, ip_buf, ip_buf_len, port);
}

int etos_socket_get_local_info(int fd, char *ip_buf, size_t ip_buf_len, int *port) {
  if (fd < 0 || !ip_buf || ip_buf_len == 0 || !port) {
    return -1;
  }

  struct sockaddr_storage addr;
  socklen_t addr_len = (socklen_t)sizeof(addr);

  if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) < 0) {
    return -1;
  }

  return extract_sockaddr_info(&addr, ip_buf, ip_buf_len, port);
}

int etos_socket_get_traffic_stats(int fd, FdTrafficStats *stats) {
  if (fd < 0 || !stats) {
    return -1;
  }

#if defined(TCP_CONNECTION_INFO)
  struct tcp_connection_info info;
  socklen_t len = (socklen_t)sizeof(info);

  if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &len) == 0) {
    atomic_store(&stats->rx_bytes, info.tcpi_rxbytes);
    atomic_store(&stats->tx_bytes, info.tcpi_txbytes);
    atomic_store(&stats->rtt_us, info.tcpi_rttcur);
    return 0;
  }
#endif

  return -1;
}

u_int64_t etos_stats_get_rx(const FdTrafficStats *stats) {
  if (!stats)
    return 0;
  return atomic_load(&stats->rx_bytes);
}

u_int64_t etos_stats_get_tx(const FdTrafficStats *stats) {
  if (!stats)
    return 0;
  return atomic_load(&stats->tx_bytes);
}

u_int32_t etos_stats_get_rtt(const FdTrafficStats *stats) {
  if (!stats)
    return 0;
  return atomic_load(&stats->rtt_us);
}
