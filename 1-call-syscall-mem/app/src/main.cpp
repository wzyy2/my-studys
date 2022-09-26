#include <malloc.h>
#include <math.h>
#include <sys/mman.h>
#include <uWS/uWS.h>
#include <iostream>
#include <thread>
#include "PID.h"
#include "boost/static_string.hpp"
#include "core_json.h"

#include "rt/MemoryPool.h"
#include "syscall-stats.h"

#define PID_thro 0  // flag

// for realtime
MemoryPool<int8_t, 1024 * 1024 * 32> pool;

template <size_t Length>
using static_strings = boost::static_string<Length>;

template <size_t N>
class rt_string : public static_strings<N> {
 public:
  rt_string(const char *str) : static_strings<N>(str) {}
  rt_string(const char *str, int length) : static_strings<N>(str, length) {}
  rt_string(static_strings<N> str) : static_strings<N>(str) {}
  rt_string() : static_strings<N>() {}

  void *operator new(size_t sz) {
    void *a = pool.allocate(sz);
    return a;
  }

  void operator delete(void *p) { pool.deallocate(reinterpret_cast<int8_t *>(p)); }
};

// For converting back and forth between radians and degrees.
constexpr double pi() { return M_PI; }
double deg2rad(double x) { return x * pi() / 180; }
double rad2deg(double x) { return x * 180 / pi(); }

// Checks if the SocketIO event has JSON data.
// If there is data the JSON object in string format will be returned,
// else the empty string "" will be returned.
rt_string<1024 * 32> hasData(rt_string<1024 * 32> s) {
  auto found_null = s.find("null");
  auto b1 = s.find_first_of("[");
  auto b2 = s.find_last_of("]");
  if (found_null != std::string::npos) {
    return "";
  } else if (b1 != std::string::npos && b2 != std::string::npos) {
    return s.substr(b1, b2 - b1 + 1);
  }
  return "";
}

// Reset the car back to starting position, and it can be used in twiddle
void Restart(uWS::WebSocket<uWS::SERVER> ws) {
  std::string reset_msg = "42[\"reset\",{}]";
  ws.send(reset_msg.data(), reset_msg.length(), uWS::OpCode::TEXT);
}

int main() {
  uWS::Hub h;

  /* Now lock all current and future pages
     from preventing of being paged */
  if (mlockall(MCL_CURRENT | MCL_FUTURE)) perror("mlockall failed:");

  /* Turn off malloc trimming.*/
  mallopt(M_TRIM_THRESHOLD, -1);

  /* Turn off mmap usage. */
  mallopt(M_MMAP_MAX, 0);

  // difine the PID controller for both steering angle, and throttle
  PID pid_steer;
  pid_steer.Init(0.1, 0.001, 2.8);

  PID pid_throttle;

#if PID_thro
  pid_throttle.Init(0.45, 0.000, 0.5);
#endif

  h.onMessage([&pid_steer, &pid_throttle](uWS::WebSocket<uWS::SERVER> ws, char *data, size_t length,
                                          uWS::OpCode opCode) {
    // "42" at the start of the message means there's a websocket message event.
    // The 4 signifies a websocket message
    // The 2 signifies a websocket event
    StatsThreadLocal::getInstance().SetEnable();

    auto t1 = std::chrono::high_resolution_clock::now();

    if (length && length > 2 && data[0] == '4' && data[1] == '2') {
      auto s = hasData(rt_string<1024 * 32>(data).substr(0, length));
      if (s != "") {
        JSONStatus_t result;
        char *value;
        size_t valueLength;

        // Calling JSON_Validate() is not necessary if the document is guaranteed to be valid.
        result = JSON_Validate(const_cast<char *>(s.c_str()), s.length());
        if (result != JSONSuccess) {
          return;
        }
        result = JSON_Search(const_cast<char *>(s.c_str()), s.length(), "[0]", sizeof("[0]") - 1, &value,
                             &valueLength);
        rt_string<64> event(value, valueLength);
        StatsThreadLocal::getInstance().PrintStats();
        StatsThreadLocal::getInstance().SetDisable();
        if (event == "telemetry") {
          // j[1] is the data JSON object
          result = JSON_Search(const_cast<char *>(s.c_str()), s.length(), "[1].cte", sizeof("[1].cte") - 1,
                               &value, &valueLength);
          char *end_ptr = value + valueLength;
          double cte = strtod(value, &end_ptr);
          result = JSON_Search(const_cast<char *>(s.c_str()), s.length(), "[1].speed", sizeof("[1].speed") - 1,
                               &value, &valueLength);
          double speed = strtod(value, &end_ptr);
          result = JSON_Search(const_cast<char *>(s.c_str()), s.length(), "[1].steering_angle",
                               sizeof("[1].steering_angle") - 1, &value, &valueLength);
          double angle = strtod(value, &end_ptr);
          double steer_value;
          double throttle = 0.2;
          // PID steering controller processing
          pid_steer.UpdateError(cte);
          steer_value = pid_steer.OutputSteerAng();

          // PID throttle controller processing
#if PID_thro
          double max_throttle = 0.8;
          pid_throttle.UpdateError(fabs(steer_value));
          throttle = pid_throttle.OutputThrottle(max_throttle);
#endif
          // Print the results
          std::cout << std::fixed;
          std::cout << "CTE: " << cte << "\t Steering: " << steer_value
                    << "\t throttle: " << throttle << std::endl;

          //           json msgJson;
          //           msgJson["steering_angle"] = steer_value;
          //           msgJson["throttle"] = throttle;
          //           rt_string<256> msg = "42[\"steer\"," + msgJson.dump() + "]";
          //           ws.send(msg.c_str(), msg.length(), uWS::OpCode::TEXT);
        }
      } else {
        // Manual driving
        rt_string<128> msg = "42[\"manual\",{}]";
        ws.send(msg.data(), msg.length(), uWS::OpCode::TEXT);
      }

      StatsThreadLocal::getInstance().PrintStats();
      StatsThreadLocal::getInstance().SetDisable();

      auto t2 = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> ms_double = t2 - t1;
      std::cout << "duration: " << ms_double.count() << "ms\n" << std::endl;
      t1 = t2;
    }
  });

  // We don't need this since we're not using HTTP but if it's removed the program
  // doesn't compile :-(
  h.onHttpRequest([](uWS::HttpResponse *res, uWS::HttpRequest req, char *data, size_t, size_t) {
    const std::string s = "<h1>Hello world!</h1>";
    if (req.getUrl().valueLength == 1) {
      res->end(s.data(), s.length());
    } else {
      // i guess this should be done more gracefully?
      res->end(nullptr, 0);
    }
  });

  h.onConnection([&h](uWS::WebSocket<uWS::SERVER> ws, uWS::HttpRequest req) {
    std::cout << "Connected!!!" << std::endl;
  });

  h.onDisconnection([&h](uWS::WebSocket<uWS::SERVER> ws, int code, char *message, size_t length) {
    ws.close();
    std::cout << "Disconnected" << std::endl;
  });

  int port = 4567;
  if (h.listen(port)) {
    std::cout << "Listening to port " << port << std::endl;
  } else {
    std::cerr << "Failed to listen to port" << std::endl;
    return -1;
  }
  h.run();
}
