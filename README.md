# libetos

[English](README.md) | [中文文档](README_CN.md)

A low-level C utility library built exclusively for the FoxTerm APP, providing core capabilities including memory buffers, encryption/decryption, networking sockets, synchronization primitives, and Base64 encoding/decoding — all designed to be wrapped and called from Swift.

> This library is a dedicated core component for the [FoxTerm](https://foxterm.app/) APP. Feel free to download it here: [https://foxterm.app/](https://foxterm.app/)

## Modules

| Header File | Description |
|-------------|-------------|
| `etos_buffer.h` | Structured contiguous memory buffer with cross-language memory mapping (Swift ↔ C) |
| `etos_socket.h` | TCP socket connections (IPv4/IPv6), proxy connections, traffic statistics, KeepAlive, DNS resolution |
| `etos_sync.h` | Mutex locks, WaitGroups, atomic operations (Atomic Int64) |
| `etos_crypto.h` | AES-256-GCM encryption/decryption, Ed25519 signing/verification, secure random number generation |
| `etos_base64.h` | Base64 encoding and decoding |

## Requirements

| Platform | Minimum Version |
|----------|-----------------|
| iOS      | 17.0            |
| macOS    | 14.0            |

## Installation

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

### Dependencies

- OpenSSL-Universal

## Core API

### Socket Networking

```c
// TCP connection (supports automatic IPv4/IPv6 resolution; ifname_or_ip can bind to a specific interface, pass NULL to skip)
int fd = etos_socket_connect("example.com", 22, 5000, NULL);

// Connect via proxy (SOCKS5 / HTTP CONNECT)
int fd = etos_socket_connect_proxy(ETOS_PROXY_SOCKS5,
    "proxy host", 1080, 5000,
    "target host", 22,
    "user", "password", NULL);

// send/recv with timeout
etos_socket_send_timeout(fd, buf, len, 0, 3000);
etos_socket_recv_timeout(fd, buf, len, 0, 3000);

// Traffic statistics
FdTrafficStats stats;
etos_socket_get_traffic_stats(fd, &stats);
uint64_t tx = etos_stats_get_tx(&stats);
uint64_t rx = etos_stats_get_rx(&stats);
uint32_t rtt = etos_stats_get_rtt(&stats);

// DNS resolution (retrieve all IPv4/IPv6 addresses)
EtosIPAddr addrs[16];
int count = etos_socket_resolve_all_ips("example.com", addrs, 16);

// Network interface info
int count;
EtosInterfaceInfo *infos = etos_socket_get_interface_infos(&count);
etos_socket_free_interface_infos(infos);

// TCP options
etos_socket_set_keepalive(fd, true, 60, 10, 3);
etos_socket_set_nodelay(fd, true);

// Connection status and shutdown
bool connected = etos_socket_is_connect(fd);
etos_socket_shutdown(fd, SHUT_RDWR);
etos_socket_close(fd);
```

### Memory Buffer

```c
etos_buffer_t *buf = etos_buffer_create(sizeof(char), 1024);
etos_buffer_copy_bytes(buf, dest, count);
etos_buffer_free(buf);
```

### Synchronization Primitives

```c
// Mutex
etos_sync_mutex_t m;
etos_sync_mutex_init(&m);
etos_sync_mutex_lock(&m);
etos_sync_mutex_unlock(&m);
etos_sync_mutex_destroy(&m);

// WaitGroup
etos_sync_waitgroup_t wg;
etos_sync_waitgroup_init(&wg);
etos_sync_waitgroup_add(&wg, 1);
etos_sync_waitgroup_done(&wg);
etos_sync_waitgroup_wait(&wg);
etos_sync_waitgroup_destroy(&wg);

// Atomic operations
etos_sync_atomic_int64_t *atom = etos_sync_atomic_create(0);
etos_sync_atomic_add(atom, 10);
etos_sync_atomic_sub(atom, 5);
int64_t val = etos_sync_atomic_load(atom);
etos_sync_atomic_store(atom, 100);
int64_t old = etos_sync_atomic_exchange(atom, 200);
etos_sync_atomic_cas(atom, 200, 300);
etos_sync_atomic_free(atom);
```

### Encryption

```c
// AES-256-GCM encryption
unsigned char key[32], iv[12], tag[16];
etos_crypto_rand_bytes(key, 32);
etos_crypto_rand_bytes(iv, 12);
etos_aes_256_gcm_encrypt(plaintext, plen, key, iv, ciphertext, &clen, tag);
etos_aes_256_gcm_decrypt(ciphertext, clen, tag, key, iv, out, &olen);

// Ed25519 signing
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

## License

MIT
