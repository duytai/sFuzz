#include "TimestampDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool timestampDependency(CallLog callLog) {
    u256 numTimestamp = 0;
    u256 numCallWithWei = 0;
    u256 numTimestampDependency = 0;
    for (auto callLogItem : callLog) {
      auto type = callLogItem.type;
      auto level = callLogItem.level;
      auto inst = callLogItem.payload.inst;
      /* level = 0 -> root call */
      if (type == CALL_OPCODE && !level) {
        if (numTimestamp && numCallWithWei) {
          numTimestampDependency += 1;
        }
        numTimestamp = 0;
        numCallWithWei = 0;
      } else if (level == 1) {
        /* level = 1 -> current contract */
        if (type == TIMESTAMP_OPCODE) numTimestamp ++;
        if (inst == Instruction::CALLCODE || inst == Instruction::CALL) {
          numCallWithWei++;
        }
      }
    }
    numTimestampDependency += (numTimestamp && numCallWithWei) ? 1 : 0;
    return !!numTimestampDependency;
  }
}

