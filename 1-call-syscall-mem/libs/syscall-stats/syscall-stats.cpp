#include "syscall-stats.h"

thread_local StatsThreadLocal StatsThreadLocal::instance_;

StatsThreadLocal::StatsThreadLocal() {
  enabled_ = false;
  memset(stats_, 0, SysCallIndex::MAX_NUM);

  if (DEBUG_THREAD_DEFAULT_ENABLE) {
    SetEnable();
  }
}

StatsThreadLocal::~StatsThreadLocal() {
#ifdef DEBUG_PRINT_WHEN_EXIT
  PrintStats();
#endif
}

void StatsThreadLocal::SetEnable() {
  enabled_ = true;
  memset(stats_, 0, SysCallIndex::MAX_NUM);
  tid_ = pthread_self();
}

void StatsThreadLocal::SetDisable() {
  enabled_ = false;
  memset(stats_, 0, SysCallIndex::MAX_NUM);
}

void StatsThreadLocal::PrintStats() {
  for (int n = 0; n < SysCallIndex::MAX_NUM; n++) {
    if (stats_[n] == 0) continue;
    std::cout << "tid: " << tid_ << " syscall-name: " << SysCallIndex::name(n)
              << "  count: " << stats_[n] << std::endl;
  }
}
uint64_t* StatsThreadLocal::GetStats() { return stats_; }
