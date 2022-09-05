/*
 * Copyright 2022 Jacob Chen
 */
#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#include "./hfsm2.hpp"

// 事件定义
struct SetTimeEvent {
  time_t ts;
};
struct StartEvent {};
struct StopEvent {};
struct InvaildEvent {};

// 状态机定义
typedef enum { sexit, start, stop, uninit } Status;
struct Context {
  time_t ts = 0;
  Status status = Status::uninit;
  std::string name;
};

using Config = hfsm2::Config ::ContextT<Context&>;

using M = hfsm2::MachineT<Config>;

using TimeServiceFSM = M::PeerRoot<struct UNINITED, struct START, struct STOP, struct EXIT>;

// forward_delcare
int sync_before_start(struct Context& context);
int regular_sync_time(struct Context& context);

// 状态定义
struct BaseReact : TimeServiceFSM::State {
  // handle a single event type - TransitionEvent
  void react(const StartEvent&, FullControl& control) noexcept {
    if (sync_before_start(control.context())) return;
    control.changeTo<START>();
  }

  void react(const StopEvent&, FullControl& control) noexcept { control.changeTo<STOP>(); }

  void react(const InvaildEvent&, FullControl& control) noexcept { control.changeTo<EXIT>(); }

  void react(const SetTimeEvent& event, FullControl& control) noexcept {
    control.context().ts = event.ts;
  }

  template <typename Event>
  void react(const Event&, FullControl&) noexcept {
    std::cout << "[unsupported transition]\n";
  }

  // 模拟现实的时间自增
  void update(FullControl& control) {
    control.context().ts += 100;
    std::cout << "node: " << control.context().name << ", time: " << control.context().ts
              << std::endl;
  }
};

struct START : BaseReact {
  using BaseReact::react;

  void enter(PlanControl& control) { control.context().status = Status::start; }
  void sexit(PlanControl& control) {}

  void update(FullControl& control) {
    BaseReact::update(control);
    regular_sync_time(control.context());
  }
};

struct STOP : BaseReact {
  using BaseReact::react;

  void enter(PlanControl& control) { control.context().status = Status::stop; }
};

struct EXIT : BaseReact {
  template <typename Event>
  void react(const Event&, FullControl&) noexcept {
    // not resumeable
  }

  void enter(PlanControl& control) { control.context().status = Status::sexit; }
};

struct UNINITED : BaseReact {
  using BaseReact::react;

  void enter(PlanControl& control) { control.context().status = Status::uninit; }
};

Context NETcontext{name : "NET"};
TimeServiceFSM::Instance NETmachine(NETcontext);

Context AMcontext{name : "AM"};
TimeServiceFSM::Instance AMmachine(AMcontext);

Context BMcontext{name : "BM"};
TimeServiceFSM::Instance BMmachine(BMcontext);

Context SENcontext{name : "SEN"};
TimeServiceFSM::Instance SENmachine(SENcontext);

int sync_before_start(struct Context& context) {
  // 同步完时间才能进入start状态
  if (context.name == "NET") {
    NETmachine.react(SetTimeEvent{0});
  } else if (context.name == "AM") {
    if (!NETmachine.isActive<START>()) return -1;
    AMmachine.react(SetTimeEvent{NETmachine.context().ts});
  } else if (context.name == "BM") {
    if (!AMmachine.isActive<START>()) return -1;
    BMmachine.react(SetTimeEvent{AMmachine.context().ts});
  } else if (context.name == "SEN") {
    if (!AMmachine.isActive<START>()) return -1;
    BMmachine.react(SetTimeEvent{AMmachine.context().ts});
  }

  return 0;
}

int regular_sync_time(struct Context& context) {
  // 同步时间
  if (context.name == "NET") {
  } else if (context.name == "AM") {
  } else if (context.name == "BM") {
    // sync time
    if (abs(AMmachine.context().ts - BMmachine.context().ts) < 1000) {
      BMmachine.react(SetTimeEvent{AMmachine.context().ts});
    }
  } else if (context.name == "SEN") {
    if (AMmachine.isActive<START>()) {
      if (abs(AMmachine.context().ts - SENmachine.context().ts) < 1000) {
        SENmachine.react(SetTimeEvent{AMmachine.context().ts});
      }
    } else if (BMmachine.isActive<START>()) {
      if (abs(BMmachine.context().ts - SENmachine.context().ts) < 1000) {
        SENmachine.react(SetTimeEvent{BMmachine.context().ts});
      }
    }
  }
  return 0;
}

// 以下是测试用例， 模拟实际运行场景， 用多个线程替代多个实例单元,  忽略同步读写
void NET() {
  while (!NETmachine.isActive<START>()) NETmachine.react(StartEvent{});

  while (!NETmachine.isActive<EXIT>()) {
    NETmachine.update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

void AM() {
  while (!AMmachine.isActive<START>()) AMmachine.react(StartEvent{});

  while (!AMmachine.isActive<EXIT>()) {
    AMmachine.update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100 + rand() % 10));
  }
}

void BM() {
  while (!BMmachine.isActive<START>()) BMmachine.react(StartEvent{});

  while (!BMmachine.isActive<EXIT>()) {
    BMmachine.update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100 + rand() % 25));
  }
}

void SEN() {
  while (!SENmachine.isActive<START>()) SENmachine.react(StartEvent{});

  while (!SENmachine.isActive<EXIT>()) {
    SENmachine.update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100 + rand() % 25));
  }
}

int main() {
  std::thread thread_net = std::thread(NET);
  std::thread thread_am = std::thread(AM);
  std::thread thread_nm = std::thread(BM);
  std::thread thread_sen = std::thread(SEN);

  // wait
  thread_net.join();

  return 0;
}
