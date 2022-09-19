#include "syscall-stats.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef ssize_t (*func_ptr_write)(int, const void*, size_t);
func_ptr_write real_write;

typedef int (*func_ptr_puts)(const char*);
func_ptr_puts real_puts;

void native_init_syscalls(void) {
  real_write = (func_ptr_write)dlsym(RTLD_NEXT, "write");
  real_puts = (func_ptr_puts)dlsym(RTLD_NEXT, "puts");
}

ssize_t write(int fd, const void* buf, size_t count) { return real_write(fd, buf, count); }

int puts(const char* str) {  return real_puts(str); }

struct initializer {
  initializer() { native_init_syscalls(); }

  ~initializer() {}
};
static initializer i;
