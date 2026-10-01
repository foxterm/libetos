#ifndef ETOS_SYNC_H
#define ETOS_SYNC_H

#include <pthread.h>
#include <stdint.h>

/* ------------------------------------------------------------
   1. 互斥锁 (pthread_mutex 实现)
   ------------------------------------------------------------ */

typedef struct {
  pthread_mutex_t lock;
} etos_sync_mutex_t;

/** 初始化互斥锁 */
void etos_sync_mutex_init(etos_sync_mutex_t *m);

/** 加锁 */
void etos_sync_mutex_lock(etos_sync_mutex_t *m);

/** 尝试加锁 (成功返回 1/true，失败返回 0/false) */
int etos_sync_mutex_trylock(etos_sync_mutex_t *m);

/** 解锁 */
void etos_sync_mutex_unlock(etos_sync_mutex_t *m);

/** 销毁互斥锁 */
void etos_sync_mutex_destroy(etos_sync_mutex_t *m);

/* ------------------------------------------------------------
   2. 等待组
   ------------------------------------------------------------ */

typedef struct {
  int count;
  pthread_mutex_t lock;
  pthread_cond_t cv;
} etos_sync_waitgroup_t;

/** 初始化等待组 */
void etos_sync_waitgroup_init(etos_sync_waitgroup_t *wg);

/** 设置/增减计数器 */
void etos_sync_waitgroup_add(etos_sync_waitgroup_t *wg, int delta);

/** 标记任务完成 (防御性扣减，决不闪退) */
void etos_sync_waitgroup_done(etos_sync_waitgroup_t *wg);

/** 等待任务归零 */
void etos_sync_waitgroup_wait(etos_sync_waitgroup_t *wg);

/** 销毁等待组 */
void etos_sync_waitgroup_destroy(etos_sync_waitgroup_t *wg);

/* ------------------------------------------------------------
   3. 原子操作 (通过 struct 封装 _Atomic 适配 Swift 导入与 C11 标准)
   ------------------------------------------------------------ */

typedef struct {
  _Atomic int64_t value;
} etos_sync_atomic_int64_t;

/** 创建并初始化一个原子变量 */
etos_sync_atomic_int64_t *etos_sync_atomic_create(int64_t initial_value);

/** 释放原子变量内存 */
void etos_sync_atomic_free(etos_sync_atomic_int64_t *addr);

/** 原子读取 */
int64_t etos_sync_atomic_load(const etos_sync_atomic_int64_t *addr);

/** 原子写入 */
void etos_sync_atomic_store(etos_sync_atomic_int64_t *addr, int64_t value);

/** 原子加 */
int64_t etos_sync_atomic_add(etos_sync_atomic_int64_t *addr, int64_t delta);

/** 原子减 */
int64_t etos_sync_atomic_sub(etos_sync_atomic_int64_t *addr, int64_t delta);

/** 原子交换 */
int64_t etos_sync_atomic_exchange(etos_sync_atomic_int64_t *addr, int64_t value);

/** 原子比较交换 (CAS) */
int64_t etos_sync_atomic_cas(etos_sync_atomic_int64_t *addr, int64_t expected, int64_t desired);

#endif /* ETOS_SYNC_H */
