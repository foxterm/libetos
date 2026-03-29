#include "etos.h"
#include <stdatomic.h>

// ---------------------------------------------------------
// 互斥锁：跨平台实现
// ---------------------------------------------------------

void etos_sync_mutex_init(etos_sync_mutex_t *m) {
#ifdef _WIN32
  InitializeCriticalSection(&m->cs);
#else
  pthread_mutex_init(&m->mutex, NULL);
#endif
}

void etos_sync_mutex_lock(etos_sync_mutex_t *m) {
#ifdef _WIN32
  EnterCriticalSection(&m->cs);
#else
  pthread_mutex_lock(&m->mutex);
#endif
}

int etos_sync_mutex_trylock(etos_sync_mutex_t *m) {
#ifdef _WIN32
  return TryEnterCriticalSection(&m->cs) != 0;
#else
  return pthread_mutex_trylock(&m->mutex) == 0;
#endif
}

void etos_sync_mutex_unlock(etos_sync_mutex_t *m) {
#ifdef _WIN32
  LeaveCriticalSection(&m->cs);
#else
  pthread_mutex_unlock(&m->mutex);
#endif
}

void etos_sync_mutex_destroy(etos_sync_mutex_t *m) {
#ifdef _WIN32
  DeleteCriticalSection(&m->cs);
#else
  pthread_mutex_destroy(&m->mutex);
#endif
}

// ---------------------------------------------------------
// 等候组：跨平台实现
// ---------------------------------------------------------

void etos_sync_waitgroup_init(etos_sync_waitgroup_t *wg) {
  wg->count = 0;

#ifdef _WIN32
  InitializeCriticalSection(&wg->lock);
  InitializeConditionVariable(&wg->cv);
#else
  pthread_mutex_init(&wg->lock, NULL);
  pthread_cond_init(&wg->cv, NULL);
#endif
}

void etos_sync_waitgroup_add(etos_sync_waitgroup_t *wg, int delta) {
#ifdef _WIN32
  EnterCriticalSection(&wg->lock);
#else
  pthread_mutex_lock(&wg->lock);
#endif

  wg->count += delta;
  if (wg->count == 0) {
#ifdef _WIN32
    WakeAllConditionVariable(&wg->cv);
#else
    pthread_cond_broadcast(&wg->cv);
#endif
  } else if (wg->count < 0) {
#ifdef _WIN32
    LeaveCriticalSection(&wg->lock);
#else
    pthread_mutex_unlock(&wg->lock);
#endif
    exit(EXIT_FAILURE);
  }

#ifdef _WIN32
  LeaveCriticalSection(&wg->lock);
#else
  pthread_mutex_unlock(&wg->lock);
#endif
}

void etos_sync_waitgroup_done(etos_sync_waitgroup_t *wg) {
  etos_sync_waitgroup_add(wg, -1);
}

void etos_sync_waitgroup_wait(etos_sync_waitgroup_t *wg) {
#ifdef _WIN32
  EnterCriticalSection(&wg->lock);
#else
  pthread_mutex_lock(&wg->lock);
#endif

  while (wg->count > 0) {
#ifdef _WIN32
    SleepConditionVariableCS(&wg->cv, &wg->lock, INFINITE);
#else
    pthread_cond_wait(&wg->cv, &wg->lock);
#endif
  }

#ifdef _WIN32
  LeaveCriticalSection(&wg->lock);
#else
  pthread_mutex_unlock(&wg->lock);
#endif
}

void etos_sync_waitgroup_destroy(etos_sync_waitgroup_t *wg) {
#ifdef _WIN32
  DeleteCriticalSection(&wg->lock);
#else
  pthread_mutex_destroy(&wg->lock);
  pthread_cond_destroy(&wg->cv);
#endif
}

// ---------------------------------------------------------
// 原子操作：使用 C11 标准原子操作 (跨平台)
// ---------------------------------------------------------

int64_t etos_sync_atomic_load(volatile int64_t *addr) {
  return atomic_load((atomic_llong *)addr);
}

void etos_sync_atomic_store(volatile int64_t *addr, int64_t value) {
  atomic_store((atomic_llong *)addr, value);
}

int64_t etos_sync_atomic_add(volatile int64_t *addr, int64_t delta) {
  return atomic_fetch_add((atomic_llong *)addr, delta);
}

int64_t etos_sync_atomic_sub(volatile int64_t *addr, int64_t delta) {
  return atomic_fetch_sub((atomic_llong *)addr, delta);
}

int64_t etos_sync_atomic_exchange(volatile int64_t *addr, int64_t value) {
  return atomic_exchange((atomic_llong *)addr, value);
}

int64_t etos_sync_atomic_cas(volatile int64_t *addr, int64_t expected,
                             int64_t desired) {
  int64_t expected_local = expected;
  atomic_compare_exchange_strong((atomic_llong *)addr, &expected_local,
                                 desired);
  return expected_local;
}
