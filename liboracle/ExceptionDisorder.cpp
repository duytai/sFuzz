#include "ExceptionDisorder.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool ExceptionDisorder::analyze(CallLog callLog) {
    auto rootCallResponse = callLog[callLog.size() - 1];
    bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
    for (auto callLogItem : callLog) {
      if (!rootException && callLogItem.payload.inst == Instruction::INVALID && callLogItem.level) {
        testData = callLog[0].payload.testData;
        return true;
      }
    }
    return false;
  }
}
