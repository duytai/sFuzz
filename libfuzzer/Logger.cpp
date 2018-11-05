#include "Logger.h"
#include <unistd.h>
#include <ctime>
#include <libdevcore/CommonIO.h>
#include <numeric>

using namespace std;
using namespace dev;

namespace fuzzer {
  void Logger::startTimer() {
    th = thread([this] () {
      auto pad = [](string str) {
        while (str.length() < 20) str += " ";
        return str;
      };
      while (true) {
        /* Each Stage */
        if (stages.size() == 0) continue;
        auto lastStage = stages.back();
        auto stageName = lastStage->name;
        auto stageFuzzed = to_string(lastStage->fuzzed) + "/" + to_string(lastStage->maxFuzzed);
        auto stageSkip = to_string(lastStage->skip);
        auto stageDuration = to_string(lastStage->duration);
        auto stageSpeed = to_string((lastStage->skip + lastStage->fuzzed) / (float)lastStage->duration);
        auto stageTestLen = to_string(lastStage->testLen);
        printf("+-------------------------------------+\n");
        printf("+             CURRENT STAGE           +\n");
        printf("+---------------+---------------------+\n");
        printf("| Stage         | %s|\n", pad(stageName).c_str());
        printf("| Fuzzed        | %s|\n", pad(stageFuzzed).c_str());
        printf("| Skip          | %s|\n", pad(stageSkip).c_str());
        printf("| Duration      | %s|\n", pad(stageDuration).c_str());
        printf("| Speed         | %s|\n", pad(stageSpeed).c_str());
        printf("| Size (bytes)  | %s|\n", pad(stageTestLen).c_str());
        printf("+---------------+---------------------+\n");
        /* Total */
        auto getFuzzed = [](int r, LogStage* n) { return r + n->fuzzed; };
        auto getDuration = [](double r, LogStage* n) { return r + n->duration; };
        auto totalFuzzed = accumulate(stages.begin(), stages.end(), 0, getFuzzed);
        auto totalDuration = accumulate(stages.begin(), stages.end(), 0.0, getDuration);
        auto avgSpeed = (float) totalFuzzed / (float) totalDuration;
        printf("+             ALL STAGES              +\n");
        printf("+---------------+---------------------+\n");
        printf("| Total Fuzzed  | %s|\n", pad(to_string(totalFuzzed)).c_str());
        printf("| Total Duration| %s|\n", pad(to_string(totalDuration)).c_str());
        printf("| Avg Speed     | %s|\n", pad(to_string(avgSpeed)).c_str());
        printf("+---------------+---------------------+\n");
        
        for (int i = 0; i < 16; i += 1) {
           cout << "\x1b[A";
        }
        usleep(100000);
      }
    });
  }
  
  void Logger::endTimer() {
    usleep(100000);
    for (int i = 0; i < 16; i += 1) {
      cout << endl;
    }
    th.detach();
  }
}
