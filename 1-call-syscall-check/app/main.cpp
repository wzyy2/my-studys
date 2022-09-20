/*
 * Copyright 2022 Jacob Chen
 */
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#include <dlfcn.h>
#include <grp.h>
#include <linux/bpf.h>
#include <linux/futex.h>
#include <linux/sysctl.h>
#include <mqueue.h>
#include <numaif.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <iostream>

int main() {
  std::cout << "Hello<cout>" << std::endl;
  printf("Hello<printf>\n");
  write(0, "Hello<write>\n", 15);

  return 0;
}
