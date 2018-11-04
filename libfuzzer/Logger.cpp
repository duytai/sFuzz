#include "Logger.h"
#include <unistd.h>
#include <ctime>
#include <libdevcore/CommonIO.h>

using namespace std;
using namespace dev;

namespace fuzzer {
  Logger::Logger() {
    entry.fuzzed = 0;
    entry.isStop = false;
  }
  
  void Logger::startTimer() {
    th = thread([this] () {
      Timer timer;
      vector<string>::size_type i;
      vector<string> headers = {
        "Fuzzed",
        "Speed "
      };
      while (!entry.isStop) {
        /* 100 ms */
        vector<double> body = {
          entry.fuzzed,
          round((float)entry.fuzzed / (float) timer.elapsed())
        };
        for (i = 0; i < headers.size(); i += 1) {
          cout << headers[i] <<  " : " << body[i] << endl;
        }
        /* Move cursor up */
        while (i > 0) {
          cout << "\x1b[A";
          i --;
        }
        usleep(100000);
      }
      for (i = 0; i < headers.size(); i += 1) {
        cout << endl;
      }
    });
  }
  
  void Logger::endTimer() {
    entry.isStop = true;
    th.join();
  }
}
