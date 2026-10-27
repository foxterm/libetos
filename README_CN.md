# libetos

[English](README.md) | [中文文档](README_CN.md)

FoxTerm APP 专用底层 C 工具库，提供内存缓冲区、加密解密、网络 Socket、同步原语、Base64 编解码、网络唤醒（Wake-on-LAN）及 ICMP 诊断（Ping/Traceroute）等核心能力，供上层 Swift 封装调用。

> 本库为 [FoxTerm](https://foxterm.app/) APP 专用核心组件，欢迎下载使用：[https://foxterm.app/](https://foxterm.app/)

## 模块

| 头文件 | 功能 |
|--------|------|
| `etos_buffer.h` | 结构化连续内存缓冲区，跨语言内存映射（Swift ↔ C） |
| `etos_socket.h` | TCP Socket 连接（IPv4/IPv6）、代理连接、流量统计、KeepAlive、域名解析 |
| `etos_sync.h` | 互斥锁（Mutex）、等待组（WaitGroup）、原子操作（Atomic Int64） |
| `etos_crypto.h` | AES-256-GCM 加解密、Ed25519 签名验签、强随机数生成 |
| `etos_base64.h` | Base64 编解码 |
| `etos_wol.h` | Wake-on-LAN 魔法包构造与发送（UDP 广播） |
| `etos_icmp.h` | ICMP 诊断：单次 Echo（Ping）和 Traceroute 跳（IPv4/IPv6，沙盒合规） |

## 环境要求

| 平台 | 最低版本 |
|------|---------|
| iOS  | 17.0    |
| macOS | 14.0   |

## 安装

### Swift Package Manager

```swift
.package(url: "https://github.com/foxterm/libetos.git", branch: "main"),
```

```swift
.product(name: "libetos", package: "libetos"),
```

### CocoaPods

```ruby
pod 'libetos', :git => 'https://github.com/foxterm/libetos.git'
```

### 依赖

- [OpenSSL](https://github.com/foxterm/OpenSSL)

## 核心 API

### Socket 网络

```c
// TCP 连接（支持 IPv4/IPv6 自动解析，ifname_or_ip 可绑定网卡，传 NULL 跳过）
int fd = etos_socket_connect("example.com", 22, 5000, NULL);

// 通过代理连接（SOCKS5 / HTTP CONNECT）
int fd = etos_socket_connect_proxy(ETOS_PROXY_SOCKS5,
    "proxy host", 1080, 5000,
    "target host", 22,
    "user", "password", NULL);

// 带超时的 send/recv
etos_socket_send_timeout(fd, buf, len, 0, 3000);
etos_socket_recv_timeout(fd, buf, len, 0, 3000);

// 流量统计
FdTrafficStats stats;
etos_socket_get_traffic_stats(fd, &stats);
uint64_t tx = etos_stats_get_tx(&stats);
uint64_t rx = etos_stats_get_rx(&stats);
uint32_t rtt = etos_stats_get_rtt(&stats);

// 域名解析（获取所有 IPv4/IPv6 地址）
EtosIPAddr addrs[16];
int count = etos_socket_resolve_all_ips("example.com", addrs, 16);

// 网卡信息
int count;
EtosInterfaceInfo *infos = etos_socket_get_interface_infos(&count);
etos_socket_free_interface_infos(infos);

// TCP 选项
etos_socket_set_keepalive(fd, true, 60, 10, 3);
etos_socket_set_nodelay(fd, true);

// 连接状态与关闭
bool connected = etos_socket_is_connect(fd);
etos_socket_shutdown(fd, SHUT_RDWR);
etos_socket_close(fd);
```

### 内存缓冲区

```c
etos_buffer_t *buf = etos_buffer_create(sizeof(char), 1024);
etos_buffer_copy_bytes(buf, dest, count);
etos_buffer_free(buf);
```

### 同步原语

```c
// 互斥锁
etos_sync_mutex_t m;
etos_sync_mutex_init(&m);
etos_sync_mutex_lock(&m);
etos_sync_mutex_unlock(&m);
etos_sync_mutex_destroy(&m);

// 等待组
etos_sync_waitgroup_t wg;
etos_sync_waitgroup_init(&wg);
etos_sync_waitgroup_add(&wg, 1);
etos_sync_waitgroup_done(&wg);
etos_sync_waitgroup_wait(&wg);
etos_sync_waitgroup_destroy(&wg);

// 原子操作
etos_sync_atomic_int64_t *atom = etos_sync_atomic_create(0);
etos_sync_atomic_add(atom, 10);
etos_sync_atomic_sub(atom, 5);
int64_t val = etos_sync_atomic_load(atom);
etos_sync_atomic_store(atom, 100);
int64_t old = etos_sync_atomic_exchange(atom, 200);
etos_sync_atomic_cas(atom, 200, 300);
etos_sync_atomic_free(atom);
```

### 加密

```c
// AES-256-GCM 加密
unsigned char key[32], iv[12], tag[16];
etos_crypto_rand_bytes(key, 32);
etos_crypto_rand_bytes(iv, 12);
etos_aes_256_gcm_encrypt(plaintext, plen, key, iv, ciphertext, &clen, tag);
etos_aes_256_gcm_decrypt(ciphertext, clen, tag, key, iv, out, &olen);

// Ed25519 签名
etos_ed25519_sign(msg, msg_len, priv_key, sig);
etos_ed25519_verify(msg, msg_len, pub_key, sig);
```

### Base64

```c
char *encoded = etos_base64_encode("hello");
char *encoded2 = etos_base64_encode_bytes(data, len);

size_t out_len;
unsigned char *decoded = etos_base64_decode(encoded, &out_len);

etos_base64_free(encoded);
etos_base64_free(decoded);
```

### 网络唤醒 (WOL)

```c
// 解析 MAC 地址字符串（支持 ":" 或 "-" 分隔）
EtosMACAddr mac;
etos_wol_parse_mac("AA:BB:CC:DD:EE:FF", &mac);

// 向指定广播地址发送
etos_wol_send(&mac, "192.168.1.255", NULL);

// 字符串便捷接口（默认广播到 255.255.255.255）
etos_wol_send_str("AA:BB:CC:DD:EE:FF", NULL, NULL);

// 向所有本地子网广播地址发送（自动检测网卡）
etos_wol_send_all(&mac, NULL);

// 自定义选项
EtosWOLOptions opts = etos_wol_default_options();
opts.port = 7;                // 使用端口 7 而非默认的 9
opts.bind_ifname = "en0";     // 绑定到指定网卡
opts.repeat_count = 3;        // 发送 3 次
opts.interval_ms = 200;       // 每次间隔 200ms
etos_wol_send_all(&mac, &opts);
```

### ICMP 诊断（Ping & Traceroute）

```c
// 单次 Ping（直接返回，调用方控制循环）
EtosICMPResult result;
etos_icmp_echo("example.com", 3000, &result);
if (result.success) {
    printf("来自 %s 的回复: 时间=%.2fms\n", result.ip, result.rtt_ms);
} else {
    printf("错误: %s\n", etos_icmp_strerror(result.error_code));
}

// 连续 Ping（调用方控制循环）
for (int i = 0; i < 10; i++) {
    EtosICMPResult r;
    etos_icmp_echo("example.com", 3000, &r);
    if (r.success) {
        printf("seq=%d 时间=%.2fms\n", i + 1, r.rtt_ms);
    }
    sleep(1); // 1 秒间隔
}

// 单次 Traceroute 跳（直接返回，调用方控制 TTL）
int ttl = 1;
while (ttl <= 30) {
    EtosICMPResult hop;
    int ret = etos_icmp_traceroute_hop("example.com", ttl, 3000, &hop);
    
    if (hop.success) {
        printf("%2d  %s  %.2f ms\n", ttl, hop.ip, hop.rtt_ms);
    } else {
        printf("%2d  * * *\n", ttl);
    }
    
    if (ret == 1) break; // 到达目标
    ttl++;
}
```

## 许可证

MIT
