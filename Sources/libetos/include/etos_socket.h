#ifndef ETOS_SOCKET_H
#define ETOS_SOCKET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef int etos_socket_t;

/* 代理类型定义 */
#define ETOS_PROXY_NONE 0
#define ETOS_PROXY_SOCKS5 1
#define ETOS_PROXY_HTTP 2

/* 常规常量定义 */
#define ETOS_INVALID_SOCKET (-1)

/* ------------------------------------------------------------
   网卡与 IP 映射数据结构
   ------------------------------------------------------------ */
typedef struct {
  char ifname[32]; /* 网卡名称，如 "en0" */
  char ip[64];     /* 主 IP 地址(优先 IPv4，无 IPv4 则显示 IPv6) */
} EtosInterfaceInfo;

/* ------------------------------------------------------------
   流量统计数据结构
   ------------------------------------------------------------ */
typedef struct {
  _Atomic uint64_t rx_bytes; /* 接收总字节数 */
  _Atomic uint64_t tx_bytes; /* 发送总字节数 */
  _Atomic uint32_t rtt_us;   /* 当前实时往返时间(微秒，瞬时值) */
} FdTrafficStats;

/* ------------------------------------------------------------
   域名解析数据结构
   ------------------------------------------------------------ */
typedef struct {
  char ip[64]; /* IP 地址字符串 (支持 IPv4/IPv6) */
  int family;  /* AF_INET 或 AF_INET6 */
} EtosIPAddr;

/* ------------------------------------------------------------
   网络 I/O 服务 (macOS / iOS 专属)
   ------------------------------------------------------------ */

/** 初始化网络环境 (macOS/iOS 下为空操作) */
int etos_socket_init_env(void);

/** 清理网络环境 */
void etos_socket_cleanup_env(void);

/** 获取系统所有活动网卡名称及其对应的 IP 地址列表 */
EtosInterfaceInfo *etos_socket_get_interface_infos(int *count);

/** 释放 etos_socket_get_interface_infos 分配的内存 */
void etos_socket_free_interface_infos(EtosInterfaceInfo *infos);

/** 获取 Socket 当前累积的发送与接收流量 */
int etos_socket_get_traffic_stats(int fd, FdTrafficStats *stats);

/** 获取接收的字节数 */
uint64_t etos_stats_get_rx(const FdTrafficStats *stats);

/** 获取发送的字节数 */
uint64_t etos_stats_get_tx(const FdTrafficStats *stats);

/** 获取 RTT(Round Trip Time) */
uint32_t etos_stats_get_rtt(const FdTrafficStats *stats);

/** 解析域名并获取其所有的 IPv4 和 IPv6 地址 */
int etos_socket_resolve_all_ips(const char *host, EtosIPAddr *addrs, size_t max_addrs);

/** 创建 TCP 连接(支持 IPv4/IPv6 自动解析) */
int etos_socket_connect(const char *host, int port, int timeout_ms, const char *ifname_or_ip);

/** 通过代理创建连接 */
int etos_socket_connect_proxy(int type, const char *proxy_host, int proxy_port, int timeout_ms, const char *target_host, int target_port, const char *user, const char *password, const char *ifname_or_ip);

/** 带超时的 Send/Recv */
ssize_t etos_socket_send_timeout(int fd, const char *buf, size_t len, int flags, int timeout_ms);
ssize_t etos_socket_recv_timeout(int fd, char *buf, size_t len, int flags, int timeout_ms);

/** 原始数据收发 */
ssize_t etos_socket_send(int fd, const char *buf, size_t len, int flags);
ssize_t etos_socket_recv(int fd, char *buf, size_t len, int flags);

/** 关闭传输通道 (how: SHUT_RD=0, SHUT_WR=1, SHUT_RDWR=2) */
int etos_socket_shutdown(int fd, int how);

/** 设置阻塞或非阻塞模式 */
int etos_socket_set_blocking(int fd, bool blocking);

/** 关闭句柄并释放资源 */
void etos_socket_close(int fd);

/** 检查连接状态 */
bool etos_socket_is_connect(int fd);

/** 设置 TCP KeepAlive 参数 */
int etos_socket_set_keepalive(int fd, bool enable, int idle_sec, int interval_sec, int count);

/** 设置 TCP_NODELAY */
int etos_socket_set_nodelay(int fd, bool enable);

/** 获取当前线程最后一次错误码 */
int etos_socket_last_error(void);

/** 获取错误码描述 */
const char *etos_socket_strerror(int errnum);

/** 获取已连接套接字的远端 IP 和端口 */
int etos_socket_get_peer_info(int fd, char *ip_buf, size_t ip_buf_len, int *port);

/** 获取套接字的本地 (Client) IP 和端口 */
int etos_socket_get_local_info(int fd, char *ip_buf, size_t ip_buf_len, int *port);

#endif /* ETOS_SOCKET_H */
