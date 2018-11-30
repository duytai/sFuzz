#include "FreezingEther.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool freezingEther(CallLog callLog) {
    u256 numTransfer = 0;
    for (auto callLogItem : callLog) {
      auto type = callLogItem.type;
      auto level = callLogItem.level;
      if (type == CALL_OPCODE || type == SUICIDE_OPCODE) {
        if (level == 1) numTransfer ++;
      }
    }
    
    return !numTransfer;
  }
}

