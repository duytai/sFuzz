#include "TimestampDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool TimestampDependency::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto inst = callLogItem.payload.inst;
      auto level = callLogItem.level;
      if (level > 0) {
        if (inst == Instruction::TIMESTAMP) numTimestamp ++;
        if (inst == Instruction::CALL) numSend ++;
      }
//      if (!!numSend && !!numTimestamp && !testData.size())
//        testData = callLogItem.payload.testData;
    }
    return !!numSend && !!numTimestamp;
  }
}

