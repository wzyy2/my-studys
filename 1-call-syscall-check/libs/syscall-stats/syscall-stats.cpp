#include "syscall-stats.h"

thread_local StatsThreadLocal StatsThreadLocal::instance_;

StatsThreadLocal::StatsThreadLocal() {
  enabled_ = DEBUG_THREAD_DEFAULT_ENABLE;
  memset(stats_, 0, SysCallIndex::MAX_NUM);
}

StatsThreadLocal::~StatsThreadLocal() {
#ifdef DEBUG_PRINT_WHEN_EXIT
  PrintStats();
#endif
}

void StatsThreadLocal::SetEnable() {
  enabled_ = true;
  memset(stats_, 0, SysCallIndex::MAX_NUM);
}

void StatsThreadLocal::SetDisable() {
  enabled_ = false;
  memset(stats_, 0, SysCallIndex::MAX_NUM);
}

void StatsThreadLocal::PrintStats() {
  for (int n = 0; n < SysCallIndex::MAX_NUM; n++) {
    if (stats_[n] == 0) continue;
    std::cout << "syscall-name: " << SysCallIndex::name(n) << "  count: " << stats_[n] << std::endl;
  }
}
