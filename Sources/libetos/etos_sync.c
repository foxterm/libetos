#include "etos_sync.h"
#include <stdatomic.h>
#include <stdlib.h>

// ---------------------------------------------------------
// 1. 互斥锁全平台适配实现
// ---------------------------------------------------------

void etos_sync_mutex_init(etos_sync_mutex_t *m) {
  if (!m)
    return;
#if defined(__APPLE__)
  m->lock = OS_UNFAIR_LOCK_INIT;
#elif defined(_WIN32)
  InitializeCriticalSection(&m->lock);
#else
  pthread_mutex_init(&m->lock, NULL);
#endif
}

void etos_sync_mutex_lock(etos_sync_mutex_t *m) {
  if (!m)
    return;
#if defined(__APPLE__)
  os_unfair_lock_lock(&m->lock);
#elif defined(_WIN32)
  EnterCriticalSection(&m->lock);
#else
  pthread_mutex_lock(&m->lock);
#endif
}

int etos_sync_mutex_trylock(etos_sync_mutex_t *m) {
  if (!m)
    return 0;
#if defined(__APPLE__)
  return os_unfair_lock_trylock(&m->lock) ? 1 : 0;
#elif defined(_WIN32)
  // TryEnterCriticalSection 成功返回非零 (BOOL)，失败返回 0
  return TryEnterCriticalSection(&m->lock) != 0 ? 1 : 0;
#else
  // pthread_mutex_trylock 成功返回 0，失败返回非 0 错误码
  return (pthread_mutex_trylock(&m->lock) == 0) ? 1 : 0;
#endif
}

void etos_sync_mutex_unlock(etos_sync_mutex_t *m) {
  if (!m)
    return;
#if defined(__APPLE__)
  os_unfair_lock_unlock(&m->lock);
#elif defined(_WIN32)
  LeaveCriticalSection(&m->lock);
#else
  pthread_mutex_unlock(&m->lock);
#endif
}

void etos_sync_mutex_destroy(etos_sync_mutex_t *m) {
  if (!m)
    return;
#if defined(_WIN32)
  DeleteCriticalSection(&m->lock);
#elif !defined(__APPLE__)
  // os_unfair_lock 为值类型无动态资源，仅非 Apple 的 POSIX 系统需要 destroy
  pthread_mutex_destroy(&m->lock);
#endif
}

// ---------------------------------------------------------
// 2. 等候组实现 (绝对防御，防负数崩溃，防销毁死锁)
// ---------------------------------------------------------

void etos_sync_waitgroup_init(etos_sync_waitgroup_t *wg) {
  if (!wg)
    return;
  wg->count = 0;
  pthread_mutex_init(&wg->lock, NULL);
  pthread_cond_init(&wg->cv, NULL);
}

void etos_sync_waitgroup_add(etos_sync_waitgroup_t *wg, int delta) {
  if (!wg)
    return;
  pthread_mutex_lock(&wg->lock);

  if (delta > 0) {
    wg->count += delta;
  } else if (delta < 0) {
    int decrement = -delta;
    if (wg->count <= decrement) {
      wg->count = 0;
      pthread_cond_broadcast(&wg->cv);
    } else {
      wg->count -= decrement;
    }
  }

  pthread_mutex_unlock(&wg->lock);
}

void etos_sync_waitgroup_done(etos_sync_waitgroup_t *wg) {
  if (!wg)
    return;
  pthread_mutex_lock(&wg->lock);

  // 防御性扣减：哪怕没 add 或重复 done，也维持在 0，绝不崩溃
  if (wg->count > 0) {
    wg->count--;
    if (wg->count == 0) {
      pthread_cond_broadcast(&wg->cv);
    }
  }

  pthread_mutex_unlock(&wg->lock);
}

void etos_sync_waitgroup_wait(etos_sync_waitgroup_t *wg) {
  if (!wg)
    return;
  pthread_mutex_lock(&wg->lock);

  while (wg->count > 0) {
    pthread_cond_wait(&wg->cv, &wg->lock);
  }

  pthread_mutex_unlock(&wg->lock);
}

void etos_sync_waitgroup_destroy(etos_sync_waitgroup_t *wg) {
  if (!wg)
    return;
  pthread_mutex_lock(&wg->lock);

  // 1. 先置 0 并唤醒潜在等待线程，避免死锁
  wg->count = 0;
  pthread_cond_broadcast(&wg->cv);

  pthread_mutex_unlock(&wg->lock);

  // 2. 销毁 POSIX 对象
  pthread_mutex_destroy(&wg->lock);
  pthread_cond_destroy(&wg->cv);
}

// ---------------------------------------------------------
// 3. 原子操作实现 (兼容 Swift 桥接 + 安全内存管理)
// ---------------------------------------------------------

etos_sync_atomic_int64_t *etos_sync_atomic_create(int64_t initial_value) {
  etos_sync_atomic_int64_t *ptr = (etos_sync_atomic_int64_t *)malloc(sizeof(etos_sync_atomic_int64_t));
  if (ptr) {
    atomic_init(&ptr->value, initial_value);
  }
  return ptr;
}

void etos_sync_atomic_free(etos_sync_atomic_int64_t *addr) {
  if (addr) {
    free(addr);
  }
}

int64_t etos_sync_atomic_load(const etos_sync_atomic_int64_t *addr) {
  if (!addr)
    return 0;
  return atomic_load_explicit(&addr->value, memory_order_seq_cst);
}

void etos_sync_atomic_store(etos_sync_atomic_int64_t *addr, int64_t value) {
  if (!addr)
    return;
  atomic_store_explicit(&addr->value, value, memory_order_seq_cst);
}

int64_t etos_sync_atomic_add(etos_sync_atomic_int64_t *addr, int64_t delta) {
  if (!addr)
    return 0;
  return atomic_fetch_add_explicit(&addr->value, delta, memory_order_seq_cst);
}

int64_t etos_sync_atomic_sub(etos_sync_atomic_int64_t *addr, int64_t delta) {
  if (!addr)
    return 0;
  return atomic_fetch_sub_explicit(&addr->value, delta, memory_order_seq_cst);
}

int64_t etos_sync_atomic_exchange(etos_sync_atomic_int64_t *addr, int64_t value) {
  if (!addr)
    return 0;
  return atomic_exchange_explicit(&addr->value, value, memory_order_seq_cst);
}

int64_t etos_sync_atomic_cas(etos_sync_atomic_int64_t *addr, int64_t expected, int64_t desired) {
  if (!addr)
    return 0;
  int64_t expected_local = expected;
  atomic_compare_exchange_strong_explicit(
      &addr->value, &expected_local, desired,
      memory_order_seq_cst, memory_order_seq_cst);
  return expected_local;
}
