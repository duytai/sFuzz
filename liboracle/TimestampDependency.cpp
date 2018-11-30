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
      if (type == CALL_OPCODE && !level) {
        if (numTimestamp && numCallWithWei) {
          numTimestampDependency += 1;
        }
        numTimestamp = 0;
        numCallWithWei = 0;
      } else {
        if (type == TIMESTAMP_OPCODE && level == 1) numTimestamp ++;
        if (type == CALL_OPCODE && level == 1) {
          auto payload = callLogItem.payload;
          if (payload.wei) {
            numCallWithWei ++;
          }
        }
      }
    }
    numTimestampDependency += (numTimestamp && numCallWithWei) ? 1 : 0;
    return !!numTimestampDependency;
  }
}

