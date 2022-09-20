#ifndef SYSCALL_STATS_HEADER
#define SYSCALL_STATS_HEADER

#include "syscall.h"

#include <cstdlib>
#include <iostream>
#include <thread>

class StatsThread {
 public:
  static StatsThread &getInstance() { return instance_; }
  StatsThread(const StatsThread &) = delete;
  StatsThread(StatsThread &&) = delete;

  // 不能用std::string， 会涉及动态内存调用
  void inline DoStats(int index){

  };

  void SetEnable();
  void SetDisable();

 private:
  static thread_local StatsThread instance_;
  StatsThread();
  bool enabled_;

  uint64_t stats_[SysCallIndex::MAX_NUM];
};

#endif
