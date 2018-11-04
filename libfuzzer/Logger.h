#include <iostream>
#include <thread>

using namespace std;

namespace fuzzer {
  struct LogEntry {
    double fuzzed;
    bool isStop;
  };
  
  class Logger {
    thread th;
    public:
      LogEntry entry;
      Logger();
      void startTimer();
      void endTimer();
  };
}

