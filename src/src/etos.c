#include "etos.h"
#include "libssh2.h"

static volatile int64_t is_initialized = 0;

int etos_init(void) {
  if (etos_sync_atomic_add(&is_initialized, 1) > 1)
    return 0;
  if (libssh2_init(0) != 0) {
    etos_sync_atomic_add(&is_initialized, -1);
    return -1;
  }
  return 0;
}
void etos_cleanup(void) {
  if (etos_sync_atomic_add(&is_initialized, -1) == 0) {
    libssh2_exit();
  }
}
