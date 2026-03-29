#include "etos.h"
#include "ssl.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
// --- 跨平台头文件和定义 ---
#ifdef _WIN32
#include <mstcpip.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define SOCKET_CLOSE closesocket
#define SOCKET_ERROR_VAL SOCKET_ERROR
#define INVALID_SOCKET_VAL INVALID_SOCKET
#define ETOS_SOCKET_LAST_ERROR WSAGetLastError()
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#define SOCKET_CLOSE close
#define SOCKET_ERROR_VAL -1
#define INVALID_SOCKET_VAL -1
#define SD_RECEIVE SHUT_RD
#define SD_SEND SHUT_WR
#define SD_BOTH SHUT_RDWR
#endif

// 兼容性宏：处理 macOS 和 Linux 的差异
#ifndef TCP_KEEPIDLE
#ifdef TCP_KEEPALIVE
#define TCP_KEEPIDLE TCP_KEEPALIVE
#else
#define TCP_KEEPIDLE 4 // 兜底值
#endif
#endif

// --- 内部辅助函数 ---
int _etos_internal_set_blocking(SOCKET fd, bool blocking) {
  if (fd == INVALID_SOCKET_VAL || fd <= 0)
    return ETOS_ERROR;

#ifdef _WIN32
  u_long mode = blocking ? 0 : 1;
  return (ioctlsocket(fd, FIONBIO, &mode) == SOCKET_ERROR) ? ETOS_ERROR : 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    return ETOS_ERROR;
  flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
  return (fcntl(fd, F_SETFL, flags) == -1) ? ETOS_ERROR : 0;
#endif
}

// 统一设置 TTL / Hop Limit
void _etos_socket_set_ttl(SOCKET fd, int ai_family, int ttl) {
  if (fd == INVALID_SOCKET_VAL || ttl <= 0)
    return;

  if (ai_family == AF_INET) {
    setsockopt(fd, IPPROTO_IP, IP_TTL, (const void *)&ttl, sizeof(ttl));
  } else if (ai_family == AF_INET6) {
    setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (const void *)&ttl,
               sizeof(ttl));
  }
}

void _etos_socket_set_window_size(SOCKET fd, int window, int scale) {
  if (fd == INVALID_SOCKET_VAL || window <= 0)
    return;

  int total_buffer = (scale > 0) ? (window << scale) : window;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const void *)&total_buffer,
             sizeof(total_buffer));
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const void *)&total_buffer,
             sizeof(total_buffer));
}

// --- 连接函数 ---
SOCKET etos_socket_connect(const char *host, int port, int timeout_ms, int ttl,
                           int window, int scale) {
  struct addrinfo hints, *res = NULL, *ptr = NULL;
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port_str, &hints, &res) != 0)
    return (SOCKET)ETOS_ERROR;

  SOCKET fd = INVALID_SOCKET_VAL;
  for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
    fd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if (fd == INVALID_SOCKET_VAL)
      continue;

    _etos_socket_set_ttl(fd, ptr->ai_family, ttl);
    _etos_socket_set_window_size(fd, window, scale);
    _etos_internal_set_blocking(fd, false);

    if (connect(fd, ptr->ai_addr, (socklen_t)ptr->ai_addrlen) ==
        SOCKET_ERROR_VAL) {
#ifdef _WIN32
      if (WSAGetLastError() == WSAEWOULDBLOCK)
#else
      if (errno == EINPROGRESS)
#endif
      {
        fd_set wfds, efds;
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        FD_SET(fd, &wfds);
        FD_SET(fd, &efds);

        struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
#ifdef _WIN32
        if (select(0, NULL, &wfds, &efds, &tv) <= 0 || FD_ISSET(fd, &efds))
#else
        if (select(fd + 1, NULL, &wfds, &efds, &tv) <= 0 || FD_ISSET(fd, &efds))
#endif
        {
          SOCKET_CLOSE(fd);
          fd = INVALID_SOCKET_VAL;
          continue;
        }

        // 检查socket是否真的连接成功
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&error, &len) < 0 ||
            error != 0) {
          SOCKET_CLOSE(fd);
          fd = INVALID_SOCKET_VAL;
          continue;
        }
      } else {
        SOCKET_CLOSE(fd);
        fd = INVALID_SOCKET_VAL;
        continue;
      }
    }
    break;
  }
  freeaddrinfo(res);


  return fd;
}

// 全能代理连接
SOCKET etos_socket_connect_proxy(int type, const char *proxy_host,
                                 int proxy_port, int timeout_ms,
                                 const char *target_host, int target_port,
                                 const char *user, const char *password,
                                 bool ssl_verify, const char *sni_host,
                                 SSL **out_ssl) {

  // 1. 物理连接
  SOCKET fd = etos_socket_connect(proxy_host, proxy_port, timeout_ms, 0, 0, 0);
  if (fd == INVALID_SOCKET_VAL || fd == (SOCKET)ETOS_ERROR)
    return (SOCKET)ETOS_ERROR;

  _etos_internal_set_blocking(fd, true);
  int success = 0;

  // --- SOCKS5 握手 ---
  if (type == ETOS_PROXY_SOCKS5) {
    unsigned char buf[1024];
    unsigned char hello[] = {0x05, 0x02, 0x00, 0x02};
    if (send(fd, (char *)hello, 4, 0) != 4 ||
        recv(fd, (char *)buf, 2, 0) != 2 || buf[0] != 0x05)
      goto failed;

    if (buf[1] == 0x02) {
      if (!user || !password)
        goto failed;
      size_t ulen = strlen(user), plen = strlen(password);
      if (ulen > 255 || plen > 255)
        goto failed;

      unsigned char auth[515];
      auth[0] = 0x01;
      auth[1] = (unsigned char)ulen;
      memcpy(auth + 2, user, ulen);
      auth[2 + ulen] = (unsigned char)plen;
      memcpy(auth + 3 + ulen, password, plen);

      if (send(fd, (char *)auth, (int)(3 + ulen + plen), 0) <= 0 ||
          recv(fd, (char *)buf, 2, 0) != 2 || buf[1] != 0x00)
        goto failed;
    } else if (buf[1] != 0x00)
      goto failed;

    // 连接目标
    size_t hlen = strlen(target_host);
    if (hlen > 255)
      goto failed;
    int idx = 0;
    buf[idx++] = 0x05;
    buf[idx++] = 0x01;
    buf[idx++] = 0x00;
    buf[idx++] = 0x03;
    buf[idx++] = (unsigned char)hlen;
    memcpy(buf + idx, target_host, hlen);
    idx += (int)hlen;
    unsigned short p = htons((unsigned short)target_port);
    memcpy(buf + idx, &p, 2);
    idx += 2;

    if (send(fd, (char *)buf, idx, 0) == idx &&
        recv(fd, (char *)buf, 4, 0) == 4 && buf[1] == 0x00) {
      int rem = (buf[3] == 0x01) ? 6 : (buf[3] == 0x04 ? 18 : 0);
      if (buf[3] == 0x03) {
        unsigned char dlen;
        if (recv(fd, (char *)&dlen, 1, 0) != 1)
          goto failed;
        rem = dlen + 2;
      }
      while (rem > 0) {
        size_t n = recv(fd, (char *)buf,
                        rem > (int)sizeof(buf) ? (int)sizeof(buf) : rem, 0);
        if (n <= 0)
          break;
        rem -= n;
      }
      success = 1;
    }
  }
  // --- HTTP / HTTPS CONNECT ---
  else if (type == ETOS_PROXY_HTTP || type == ETOS_PROXY_HTTPS) {
    char buf[2048], auth_line[1024] = "";
    if (user && password) {
      char creds[512];
      snprintf(creds, sizeof(creds), "%s:%s", user, password);
      char *b64 = etos_ssl_base64_encode(creds);
      if (b64) {
        snprintf(auth_line, sizeof(auth_line),
                 "Proxy-Authorization: Basic %s\r\n", b64);
        free(b64);
      }
    }
    int len = snprintf(
        buf, sizeof(buf), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%s\r\n",
        target_host, target_port, target_host, target_port, auth_line);
    if (send(fd, buf, len, 0) == len) {
      int recvd = 0;
      while (recvd < (int)sizeof(buf) - 1) {
        if (recv(fd, &buf[recvd], 1, 0) <= 0)
          break;
        recvd++;
        buf[recvd] = '\0';
        if (recvd >= 4 && memcmp(&buf[recvd - 4], "\r\n\r\n", 4) == 0) {
          if (strstr(buf, " 200 "))
            success = 1;
          break;
        }
      }
    }

    // 如果是 HTTPS 且打通了隧道，则进行 SSL 握手
    if (success && type == ETOS_PROXY_HTTPS && out_ssl) {
      if (!g_etos_ssl_ctx) {
        success = 0;
        goto failed;
      }
      *out_ssl = SSL_new(g_etos_ssl_ctx);
      if (*out_ssl) {
        const char *final_sni =
            (sni_host && strlen(sni_host) > 0) ? sni_host : target_host;
        SSL_set_fd(*out_ssl, (int)fd);
        SSL_set_tlsext_host_name(*out_ssl, final_sni);
        if (ssl_verify) {
          SSL_set_verify(*out_ssl, SSL_VERIFY_PEER, NULL);
          X509_VERIFY_PARAM_set1_host(SSL_get0_param(*out_ssl), final_sni, 0);
        } else {
          SSL_set_verify(*out_ssl, SSL_VERIFY_NONE, NULL);
        }
        if (SSL_connect(*out_ssl) <= 0)
          success = 0;
        else if (ssl_verify && SSL_get_verify_result(*out_ssl) != X509_V_OK)
          success = 0;
      } else
        success = 0;
    }
  }

failed:
  _etos_internal_set_blocking(fd, false);
  if (!success) {
    if (out_ssl && *out_ssl) {
      SSL_free(*out_ssl);
      *out_ssl = NULL;
    }
    etos_socket_close(fd);
    return (SOCKET)ETOS_ERROR;
  }
  return fd;
}
void etos_socket_keepalive(SOCKET fd) {
  if (fd == INVALID_SOCKET_VAL || fd <= 0)
    return;

#ifdef _WIN32
  struct tcp_keepalive settings;
  settings.onoff = 1;
  settings.keepalivetime = 60000;    // 毫秒 (60s)
  settings.keepaliveinterval = 5000; // 毫秒 (5s)
  DWORD bytesReturned = 0;
  WSAIoctl(fd, SIO_KEEPALIVE_VALS, &settings, sizeof(settings), NULL, 0,
           &bytesReturned, NULL, NULL);
#else
  int keepalive = 1;    // 开启开关
  int keepidle = 60;    // 60秒无数据后开始发送探测包
  int keepinterval = 5; // 探测包发送间隔
  int keepcount = 5;    // 探测失败 5 次则认为连接彻底断开

  setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval,
             sizeof(keepinterval));
  setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcount, sizeof(keepcount));
#endif
}
// 定向关闭
int etos_socket_shutdown(SOCKET fd, int how) {
  if (fd == INVALID_SOCKET_VAL || fd <= 0)
    return ETOS_ERROR;

  int sd_how = (how == 0) ? SD_RECEIVE : (how == 1 ? SD_SEND : SD_BOTH);
  if (shutdown(fd, sd_how) == SOCKET_ERROR_VAL) {
    return ETOS_ERROR;
  }
  return 0;
}

// 动态设置阻塞/非阻塞模式
int etos_socket_set_blocking(SOCKET fd, bool blocking) {
  return _etos_internal_set_blocking(fd, blocking);
}

// 错误码转换
#ifdef _WIN32
int _etos_wsa2errno(void) {
  switch (WSAGetLastError()) {
  case WSAEWOULDBLOCK:
    return EAGAIN;
  case WSAENOTSOCK:
    return EBADF;
  case WSAEINTR:
    return EINTR;
  default:
    return EIO;
  }
}
#endif

// --- 发送数据 ---
ssize_t etos_socket_send(SOCKET fd, const char *buf, ssize_t len, int flags) {
  if (fd == INVALID_SOCKET_VAL || buf == NULL || len <= 0)
    return ETOS_ERROR;

  ssize_t rc = send(fd, buf, len, flags);
  if (rc < 0) {
    int err;
#ifdef _WIN32
    err = _etos_wsa2errno();
#else
    err = errno;
#endif
    if (err == EINTR)
      return -EAGAIN;
#ifdef EWOULDBLOCK /* For VMS and other special unixes */
    if (err == EWOULDBLOCK)
      return -EAGAIN;
#endif
    return -err;
  }
  return rc;
}

// --- 接收数据 ---
ssize_t etos_socket_recv(SOCKET fd, char *buf, ssize_t len, int flags) {
  if (fd == INVALID_SOCKET_VAL || buf == NULL || len <= 0)
    return ETOS_ERROR;

  ssize_t rc = recv(fd, buf, len, flags);
  if (rc < 0) {
    int err;
#ifdef _WIN32
    err = _etos_wsa2errno();
#else
    err = errno;
#endif
    if (err == EINTR)
      return -EAGAIN;
    if (err == ENOENT)
      return -EAGAIN;
#ifdef EWOULDBLOCK
    else if (err == EWOULDBLOCK)
      return -EAGAIN;
#endif
    else
      return -err;
  }
  return rc;
}

// --- HTTPS 发送数据 (OpenSSL) ---
ssize_t etos_socket_ssl_send(SSL *ssl, const char *buf, ssize_t len,
                             int flags) {
  return etos_ssl_send(ssl, buf, len, flags);
}

// --- HTTPS 接收数据 (OpenSSL) ---
ssize_t etos_socket_ssl_recv(SSL *ssl, char *buf, ssize_t len, int flags) {
  return etos_ssl_recv(ssl, buf, len, flags);
}
// 判断 Socket FD 当前是否处于正常连接状态
bool etos_socket_is_connect(SOCKET fd) {
  if (fd == INVALID_SOCKET_VAL || fd <= 0)
    return false;

  // 1. 基础错误检查 (跨平台)
  int error = 0;
  socklen_t len = sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0) {
    return false;
  }
  if (error != 0)
    return false;

  // 2. TCP 状态检查 (仅限支持 TCP_INFO 的系统，如 Linux)
#ifdef TCP_INFO
  struct tcp_info info;
  socklen_t info_len = sizeof(info);
  if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &info_len) == 0) {
    return (info.tcpi_state == TCP_ESTABLISHED);
  }
#endif

  // 3. 探测性发送
  // Windows 不支持 MSG_NOSIGNAL，且 send 0 字节行为在各平台略有差异
#ifdef _WIN32
  // Windows 下可以通过判断错误码处理
  ssize_t res = send(fd, "", 0, 0);
  if (res == SOCKET_ERROR) {
    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK)
      return false;
  }
#else
  // Unix/macOS 使用 MSG_NOSIGNAL 防止 SIGPIPE
  ssize_t res = send(fd, NULL, 0, MSG_NOSIGNAL);
  if (res < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      return false;
  }
#endif

  return true;
}
// 彻底关闭 Socket
void etos_socket_close(SOCKET fd) {
  if (fd != INVALID_SOCKET_VAL && fd != (SOCKET)ETOS_ERROR && fd != 0) {
    shutdown(fd, SD_BOTH);
    SOCKET_CLOSE(fd);
  }
}

// 获取错误码
int etos_socket_last_error(void) {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}
