#ifndef SYSCALL_STATS_HEADER
#define SYSCALL_STATS_HEADER

#include "syscall-common.h"

// 线程singleton统计
class StatsThreadLocal {
 public:
  static StatsThreadLocal &getInstance() { return instance_; }
  StatsThreadLocal(const StatsThreadLocal &) = delete;
  StatsThreadLocal(StatsThreadLocal &&) = delete;

  // 不能用std::string， 会涉及动态内存调用
  void inline DoStats(int index) { stats_[index] += 1; }

  void PrintStats();
  void SetEnable();
  void SetDisable();

 private:
  static thread_local StatsThreadLocal instance_;
  StatsThreadLocal();
  ~StatsThreadLocal();

  bool enabled_;
  uint64_t stats_[SysCallIndex::MAX_NUM];
};

#endif
