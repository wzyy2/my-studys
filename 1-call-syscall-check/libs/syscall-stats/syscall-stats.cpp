#include "syscall-stats.h"

#include <dlfcn.h>

#include <cstdlib>
#include <iostream>
#include <thread>

// 开关参数，测试用
#define DEBUG_THREAD_ON

class StatsProcess {};

thread_local StatsThread StatsThread::instance_;

StatsThread::StatsThread() {}

struct initializer {
  initializer() {}

  ~initializer() {}
};
static initializer i;
