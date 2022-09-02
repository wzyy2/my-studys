#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "hfsm2.hpp"

// 事件定义
struct SetTimeEvent {
  time_t ts;
};
struct StartEvent {};
struct StopEvent {};
struct InvaildEvent {};

// 状态机定义
typedef enum { invaild, start, stop, uninit } Status;
struct Context {
  time_t ts = 0;
  Status status = Status::uninit;
  std::string name;
};

using Config = hfsm2::Config ::ContextT<Context&>;

using M = hfsm2::MachineT<Config>;

using TimeServiceFSM = M::PeerRoot<struct UNINITED, struct START, struct STOP, struct INVAILD>;

// 状态定义
struct BaseReact : TimeServiceFSM::State {
  // handle a single event type - TransitionEvent
  void react(const StartEvent&, FullControl& control) noexcept {
    std::cout << "  Reactive: reacting to TransitionEvent\n";

    control.changeTo<START>();
  }

  void react(const StopEvent&, FullControl& control) noexcept {
    std::cout << "  Reactive: reacting to TransitionEvent\n";

    control.changeTo<STOP>();
  }

  void react(const InvaildEvent&, FullControl& control) noexcept {
    std::cout << "  Reactive: reacting to TransitionEvent\n";

    control.changeTo<INVAILD>();
  }

  void react(const SetTimeEvent& event, FullControl& control) noexcept {
    std::cout << "  Reactive: reacting to TransitionEvent\n";

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
};

struct STOP : BaseReact {
  using BaseReact::react;

  void enter(PlanControl& control) { control.context().status = Status::stop; }
};

struct INVAILD : BaseReact {
  using BaseReact::react;

  void enter(PlanControl& control) { control.context().status = Status::invaild; }
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

// 以下是测试用例， 模拟实际运行场景， 用多个线程替代多个实例单元
void NET() {
  // 初始化时间, 然后持续自增
  NETmachine.react(SetTimeEvent{0});
  NETmachine.react(START{});

  while (true) {
    NETmachine.update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

void AM() {
  // 等待NET
  while (NETmachine.isActive<START>()) {
  };
  // 设置时间
  AMmachine.react(SetTimeEvent{});
  AMmachine.react(START{});

  while (true) {
    // 模拟时间偏差
    AMmachine.access()
    AMmachine.update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100 + rand() % 100));
  }
}

void BM() {

  while (true) {
    // 模拟时间偏差
    BMmachine.update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100 + rand() % 100));
  }
}

void SEN() {
  while (true) {
    // 模拟时间偏差
    SENmachine.update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100 + rand() % 100));
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
