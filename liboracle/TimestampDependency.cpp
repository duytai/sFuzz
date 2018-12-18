#include "TimestampDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool timestampDependency(CallLog callLog) {
    u256 numTimestamp = 0;
    u256 numSend = 0;
    for (auto callLogItem : callLog) {
      auto inst = callLogItem.payload.inst;
      auto level = callLogItem.level;
      if (level > 0) {
        if (inst == Instruction::TIMESTAMP) numTimestamp ++;
        if (inst == Instruction::CALL) numSend ++;
      }
    }
    return !!numSend && !!numTimestamp;
  }
}

