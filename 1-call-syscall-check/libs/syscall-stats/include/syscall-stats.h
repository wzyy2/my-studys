#ifndef SYSCALL_STATS_HEADER
#define SYSCALL_STATS_HEADER

#define DEBUG_LEVEL 0

#define DEBUG_MSG(level, str)      \
  if (level <= DEBUG_LEVEL) {      \
    std::cout << str << std::endl; \
  }

void native_init_syscalls();

#endif