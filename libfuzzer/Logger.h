#include <iostream>
#include <thread>
#include <vector>

using namespace std;

namespace fuzzer {
  struct LogStage {
    /* Name of stage */
    string name;
    /* Number of fuzzed test cases */
    int fuzzed;
    /* Number of skip test cases */
    int skip;
    /* Max number of fuzzed test cases */
    int maxFuzzed;
    /* Length of Test case */
    int testLen;
    /* Constructer */
    double duration;
    LogStage() {
      name = "";
      fuzzed = 0;
      skip = 0;
      maxFuzzed = 0;
      duration = 0;
    }
  };
  struct LogInfo {
    int queueSize;
    LogInfo() {
      queueSize = 0;
    }
  };
  class Logger {
    thread th;
    public:
      vector<LogStage*> stages;
      LogInfo info;
      void startTimer();
      void endTimer();
  };
}

