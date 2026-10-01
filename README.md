# ETOS C/C++ 工具库 (ETOS Native Library)

ETOS 是一个专为 C/C++ 及其上层语言封装（如 Swift/Objective-C 等）设计的底层跨平台工具库。它提供了基础内存缓存、加密解密、网络 Socket 管道、Socket 代理、同步原语与并发工具以及 Base64 编解码等高效核心模块。


## 模块概览

| 头文件 | 主要功能 | 适用场景 |
| :--- | :--- | :--- |
| `etos_buffer.h` | 结构化连续内存缓冲区管理 | 跨语言内存映射（如 Swift 与 C 通信）、数据暂存 |
| `etos_crypto.h` | 强随机数生成、AES-256-GCM 对称加密与认证 | 安全数据传输、文件加密、消息身份验证 |
| `etos_socket.h` | 高级套接字网络库（支持 IPv4/IPv6、代理、流量统计、KeepAlive 等） | 高性能网络客户端/代理通信、实时 RTT 和流量监控 |
| `etos_sync.h` | 互斥锁 (Mutex)、等待组 (WaitGroup) 及原子操作 (Atomic) | 多线程同步、并发任务等待、跨线程计数器 |
| `etos_base64.h` | Base64 编解码 | 二进制数据与文本数据的安全转换 |
