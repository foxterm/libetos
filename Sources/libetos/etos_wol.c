#include "etos_wol.h"
#include "etos_socket.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------
   内部辅助函数
   ------------------------------------------------------------ */

/** 解析单个十六进制字符，失败返回 -1 */
static int hex_char_to_int(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/** 解析两个十六进制字符为一个字节 */
static int parse_hex_byte(const char *s, uint8_t *out) {
  int hi = hex_char_to_int(s[0]);
  int lo = hex_char_to_int(s[1]);
  if (hi < 0 || lo < 0)
    return -1;
  *out = (uint8_t)((hi << 4) | lo);
  return 0;
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

/** 通过 UDP 广播发送数据到指定地址和端口 */
static int send_udp_broadcast(const uint8_t *data, size_t len, const char *broadcast_addr, int port, const char *bind_ifname) {
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
    return -1;

  int broadcast_opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast_opt, sizeof(broadcast_opt)) < 0) {
    close(fd);
    return -1;
  }

#ifdef SO_NOSIGPIPE
  int nosigpipe = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

  if (bind_ifname && bind_ifname[0] != '\0') {
    unsigned int ifindex = if_nametoindex(bind_ifname);
    if (ifindex != 0) {
#ifdef IP_BOUND_IF
      setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex));
#endif
    }
  }

  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, broadcast_addr, &dest_addr.sin_addr) != 1) {
    close(fd);
    return -1;
  }

  ssize_t sent = sendto(fd, data, len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  close(fd);

  return (sent == (ssize_t)len) ? 0 : -1;
}

/* ------------------------------------------------------------
   外部接口实现
   ------------------------------------------------------------ */

EtosWOLOptions etos_wol_default_options(void) {
  EtosWOLOptions opts;
  opts.port = ETOS_WOL_DEFAULT_PORT;
  opts.bind_ifname = NULL;
  opts.repeat_count = 1;
  opts.interval_ms = 100;
  return opts;
}

int etos_wol_parse_mac(const char *mac_str, EtosMACAddr *out_mac) {
  if (!mac_str || !out_mac)
    return -1;

  /* 跳过前导空白 */
  while (*mac_str && isspace((unsigned char)*mac_str))
    mac_str++;

  /* 检查长度: "XX:XX:XX:XX:XX:XX" = 17 字符 */
  size_t slen = strlen(mac_str);
  if (slen < 17)
    return -1;

  /* 检测分隔符 */
  char sep = mac_str[2];
  if (sep != ':' && sep != '-')
    return -1;

  uint8_t bytes[ETOS_WOL_MAC_LEN];
  for (int i = 0; i < ETOS_WOL_MAC_LEN; i++) {
    int offset = i * 3;
    if (parse_hex_byte(mac_str + offset, &bytes[i]) < 0)
      return -1;
    if (i < ETOS_WOL_MAC_LEN - 1) {
      if (mac_str[offset + 2] != sep)
        return -1;
    }
  }

  memcpy(out_mac->bytes, bytes, ETOS_WOL_MAC_LEN);
  return 0;
}

int etos_wol_build_magic_packet(const EtosMACAddr *mac, uint8_t *out_buf) {
  if (!mac || !out_buf)
    return -1;

  /* 6 字节 0xFF 前导 */
  memset(out_buf, 0xFF, ETOS_WOL_MAC_LEN);

  /* MAC 地址重复 16 次 */
  for (int i = 0; i < 16; i++) {
    memcpy(out_buf + ETOS_WOL_MAC_LEN + i * ETOS_WOL_MAC_LEN, mac->bytes, ETOS_WOL_MAC_LEN);
  }

  return 0;
}

int etos_wol_send(const EtosMACAddr *mac, const char *broadcast_addr, const EtosWOLOptions *opts) {
  if (!mac || !broadcast_addr)
    return -1;

  EtosWOLOptions effective_opts;
  if (opts) {
    effective_opts = *opts;
  } else {
    effective_opts = etos_wol_default_options();
  }

  int port = effective_opts.port > 0 ? effective_opts.port : ETOS_WOL_DEFAULT_PORT;
  int repeat = effective_opts.repeat_count > 0 ? effective_opts.repeat_count : 1;

  uint8_t magic[ETOS_WOL_MAGIC_PKT_SIZE];
  if (etos_wol_build_magic_packet(mac, magic) < 0)
    return -1;

  int last_result = -1;
  for (int i = 0; i < repeat; i++) {
    if (i > 0 && effective_opts.interval_ms > 0) {
      sleep_ms(effective_opts.interval_ms);
    }
    last_result = send_udp_broadcast(magic, ETOS_WOL_MAGIC_PKT_SIZE, broadcast_addr, port, effective_opts.bind_ifname);
  }

  return last_result;
}

int etos_wol_send_str(const char *mac_str, const char *broadcast_addr, const EtosWOLOptions *opts) {
  EtosMACAddr mac;
  if (etos_wol_parse_mac(mac_str, &mac) < 0)
    return -1;

  const char *addr = broadcast_addr ? broadcast_addr : "255.255.255.255";
  return etos_wol_send(&mac, addr, opts);
}

int etos_wol_send_all(const EtosMACAddr *mac, const EtosWOLOptions *opts) {
  if (!mac)
    return -1;

  EtosWOLOptions effective_opts;
  if (opts) {
    effective_opts = *opts;
  } else {
    effective_opts = etos_wol_default_options();
  }

  int port = effective_opts.port > 0 ? effective_opts.port : ETOS_WOL_DEFAULT_PORT;
  int repeat = effective_opts.repeat_count > 0 ? effective_opts.repeat_count : 1;

  uint8_t magic[ETOS_WOL_MAGIC_PKT_SIZE];
  if (etos_wol_build_magic_packet(mac, magic) < 0)
    return -1;

  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs(&ifaddr) < 0)
    return -1;

  int success_count = 0;

  for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
      continue;

    unsigned int flags = ifa->ifa_flags;
    if ((flags & IFF_UP) == 0 || (flags & IFF_LOOPBACK) != 0 || (flags & IFF_BROADCAST) == 0)
      continue;

    struct sockaddr_in *broad_addr = (struct sockaddr_in *)ifa->ifa_broadaddr;
    if (!broad_addr)
      continue;

    char broad_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &broad_addr->sin_addr, broad_str, sizeof(broad_str)))
      continue;

    /* 如果指定了网卡绑定，只发送到该网卡 */
    if (effective_opts.bind_ifname && effective_opts.bind_ifname[0] != '\0') {
      if (strcmp(ifa->ifa_name, effective_opts.bind_ifname) != 0)
        continue;
    }

    for (int i = 0; i < repeat; i++) {
      if (i > 0 && effective_opts.interval_ms > 0) {
        sleep_ms(effective_opts.interval_ms);
      }
      if (send_udp_broadcast(magic, ETOS_WOL_MAGIC_PKT_SIZE, broad_str, port, ifa->ifa_name) == 0) {
        success_count++;
      }
    }
  }

  freeifaddrs(ifaddr);
  return success_count > 0 ? success_count : -1;
}

int etos_wol_send_all_str(const char *mac_str, const EtosWOLOptions *opts) {
  EtosMACAddr mac;
  if (etos_wol_parse_mac(mac_str, &mac) < 0)
    return -1;

  return etos_wol_send_all(&mac, opts);
}
