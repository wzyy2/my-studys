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

#include "syscall-stats.h"

void thread_func() { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }

int main() {
  std::cout << "\ntest log" << std::endl;
  StatsThreadLocal::getInstance().SetEnable();
  std::cout << "Hello<cout>" << std::endl;
  printf("Hello<printf>\n");
  write(0, "Hello<write>\n", 15);
  StatsThreadLocal::getInstance().PrintStats();
  StatsThreadLocal::getInstance().SetDisable();

  std::cout << "\ntest file" << std::endl;
  StatsThreadLocal::getInstance().SetEnable();
  std::ofstream myfile;
  myfile.open("/tmp/example.txt");
  myfile << "Writing this to a file.\n";
  myfile.close();

  FILE* demo;
  demo = fopen("/tmp/demo_file.txt", "w+");
  fprintf(demo, "%s %s %s", "Welcome", "to", "GeeksforGeeks");
  fclose(demo);
  StatsThreadLocal::getInstance().PrintStats();
  StatsThreadLocal::getInstance().SetDisable();

  std::cout << "\ntest thread" << std::endl;
  StatsThreadLocal::getInstance().SetEnable();
  std::thread threadA = std::thread(thread_func);
  threadA.join();
  StatsThreadLocal::getInstance().PrintStats();
  StatsThreadLocal::getInstance().SetDisable();

  std::cout << "\ntest malloc" << std::endl;
  StatsThreadLocal::getInstance().SetEnable();
  auto testA = new std::vector<int>(32);
  auto testB = malloc(64);
  free(testB);
  delete testA;
  StatsThreadLocal::getInstance().PrintStats();
  StatsThreadLocal::getInstance().SetDisable();

  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  return 0;
}
