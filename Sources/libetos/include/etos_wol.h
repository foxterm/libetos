#ifndef ETOS_WOL_H
#define ETOS_WOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* WOL 魔法包常量 */
#define ETOS_WOL_MAC_LEN 6
#define ETOS_WOL_MAGIC_PKT_SIZE 102 /* 6 x 0xFF + 16 x MAC */
#define ETOS_WOL_DEFAULT_PORT 9

/* ------------------------------------------------------------
   MAC 地址数据结构
   ------------------------------------------------------------ */
typedef struct {
  uint8_t bytes[ETOS_WOL_MAC_LEN]; /* 6 字节 MAC 地址 */
} EtosMACAddr;

/* ------------------------------------------------------------
   WOL 发送选项
   ------------------------------------------------------------ */
typedef struct {
  int port;                 /* UDP 目标端口，0 表示使用默认端口 9 */
  const char *bind_ifname;  /* 绑定到指定网卡名称 (如 "en0")，NULL 表示不绑定 */
  int repeat_count;         /* 重复发送次数，0 或 1 表示只发一次 */
  int interval_ms;          /* 每次重复发送的间隔毫秒数，0 表示无间隔 */
} EtosWOLOptions;

/** 获取默认的 WOL 选项 */
EtosWOLOptions etos_wol_default_options(void);

/* ------------------------------------------------------------
   MAC 地址解析
   ------------------------------------------------------------ */

/**
 * 解析 MAC 地址字符串为 EtosMACAddr 结构
 * 支持格式: "AA:BB:CC:DD:EE:FF" 或 "AA-BB-CC-DD-EE-FF"
 * @param mac_str MAC 地址字符串
 * @param out_mac 输出解析后的 MAC 地址
 * @return 成功返回 0，失败返回 -1
 */
int etos_wol_parse_mac(const char *mac_str, EtosMACAddr *out_mac);

/* ------------------------------------------------------------
   魔法包构造
   ------------------------------------------------------------ */

/**
 * 构造 WOL 魔法包
 * @param mac 目标 MAC 地址
 * @param out_buf 输出缓冲区，长度至少为 ETOS_WOL_MAGIC_PKT_SIZE
 * @return 成功返回 0，失败返回 -1
 */
int etos_wol_build_magic_packet(const EtosMACAddr *mac, uint8_t *out_buf);

/* ------------------------------------------------------------
   WOL 发送
   ------------------------------------------------------------ */

/**
 * 向指定广播地址发送 WOL 魔法包
 * @param mac 目标 MAC 地址
 * @param broadcast_addr 广播地址字符串 (如 "255.255.255.255" 或 "192.168.1.255")
 * @param opts WOL 选项，传 NULL 使用默认选项
 * @return 成功返回 0，失败返回 -1
 */
int etos_wol_send(const EtosMACAddr *mac, const char *broadcast_addr, const EtosWOLOptions *opts);

/**
 * 向指定广播地址发送 WOL 魔法包 (MAC 字符串便捷接口)
 * @param mac_str MAC 地址字符串 ("AA:BB:CC:DD:EE:FF" 或 "AA-BB-CC-DD-EE-FF")
 * @param broadcast_addr 广播地址字符串，传 NULL 使用 "255.255.255.255"
 * @param opts WOL 选项，传 NULL 使用默认选项
 * @return 成功返回 0，失败返回 -1
 */
int etos_wol_send_str(const char *mac_str, const char *broadcast_addr, const EtosWOLOptions *opts);

/**
 * 向所有本地子网广播地址发送 WOL 魔法包
 * 自动获取本机所有活动网卡的广播地址并逐一发送
 * @param mac 目标 MAC 地址
 * @param opts WOL 选项，传 NULL 使用默认选项
 * @return 成功发送的次数 (>= 1 表示至少有一个广播成功)
 */
int etos_wol_send_all(const EtosMACAddr *mac, const EtosWOLOptions *opts);

/**
 * 向所有本地子网广播地址发送 WOL 魔法包 (MAC 字符串便捷接口)
 * @param mac_str MAC 地址字符串
 * @param opts WOL 选项，传 NULL 使用默认选项
 * @return 成功发送的次数
 */
int etos_wol_send_all_str(const char *mac_str, const EtosWOLOptions *opts);

#ifdef __cplusplus
}
#endif

#endif /* ETOS_WOL_H */
