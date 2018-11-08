#include "Logger.h"
#include <unistd.h>
#include <ctime>
#include <libdevcore/CommonIO.h>
#include <numeric>
#include "TextTable.h"

using namespace std;
using namespace dev;

namespace fuzzer {
  void Logger::startTimer() {
    th = thread([this] () {
      int numLines = 21;
      for (int i = 0; i < numLines; i += 1) {
        cout << endl;
      }
      while (true) {
        /* Each Stage */
        if (stages.size() == 0) continue;
        for (int i = 0; i < numLines; i += 1) {
          cout << "\x1b[A";
        }
        /* Table */
        auto lastStage = stages.back();
        TextTable t( '-', '|', '+' );
        t.add("  CURRENT STAGE  ");
        t.add("                     ");
        t.add("   TOTAL STAGE   ");
        t.add("                     ");
        t.endOfRow();
        t.add("Stage");
        t.add(lastStage->name);
        t.endOfRow();
        t.add("Fuzzed");
        t.add(to_string(lastStage->fuzzed) + "/" + to_string(lastStage->maxFuzzed));
        t.add("Total Fuzzed");
        auto totalFuzzed = accumulate(stages.begin(), stages.end(), 0, [](int r, LogStage* n) { return r + n->fuzzed; });
        t.add(to_string(totalFuzzed));
        t.endOfRow();
        t.add("Skip");
        t.add(to_string(lastStage->skip));
        t.add("Total Skip");
        auto totalSkip = accumulate(stages.begin(), stages.end(), 0, [](int r, LogStage* n) { return r + n->skip; });
        t.add(to_string(totalSkip));
        t.endOfRow();
        t.add("Duration");
        t.add(to_string(lastStage->duration));
        t.add("Total Duration");
        auto totalDuration = accumulate(stages.begin(), stages.end(), 0.0, [](double r, LogStage* n) { return r + n->duration; });
        t.add(to_string(totalDuration));
        t.endOfRow();
        t.add("Speed");
        t.add(to_string((lastStage->skip + lastStage->fuzzed) / (float)lastStage->duration));
        t.add("Avg Speed");
        auto avgSpeed = (totalFuzzed + totalSkip) / (float) totalDuration;
        t.add(to_string(avgSpeed));
        t.endOfRow();
        t.add("Queues");
        t.add(to_string(lastStage->numTest));
        t.add("Total Queues");
        auto totalNumTest = accumulate(stages.begin(), stages.end(), 1, [](int r, LogStage* n) { return r + n->numTest; });
        t.add(to_string(totalNumTest));
        t.endOfRow();
        t.add("Size (bytes)");
        t.add(to_string(lastStage->testLen));
        t.endOfRow();
        t.add("Errors");
        t.add(to_string(lastStage->errorCount));
        t.add("Total Errors");
        auto totalErrors = accumulate(stages.begin(), stages.end(), 0, [](int r, LogStage* n) { return r + n->errorCount; });
        t.add(to_string(totalErrors));
        t.endOfRow();
        t.add("Effector map");
        t.add(to_string(lastStage->effCount));
        t.add("Index");
        t.add(to_string(idx));
        t.endOfRow();
        cout << t;
        usleep(100000);
      }
    });
  }
  
  void Logger::endTimer() {
    usleep(100000);
    th.detach();
  }
}
