#include "syscall-stats.h"

// 在C程序中不会被调到
struct initializer {
  initializer() {
    native_init_syscalls();
  }

  ~initializer() {}
};
static initializer i;
