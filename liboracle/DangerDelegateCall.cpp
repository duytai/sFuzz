#include "DangerDelegateCall.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool dangerDelegateCall(CallLog callLog) {
    u256 numDanger = 0;
    bytes inData;
    for (auto callLogItem : callLog) {
      auto type = callLogItem.type;
      auto level = callLogItem.level;
      if (type == CALL_OPCODE && !level) {
        inData = callLogItem.payload.data;
      }
      if (type == CALL_OPCODE && !!level) {
        auto inst = callLogItem.payload.inst;
        if (inst == Instruction::DELEGATECALL) {
          if (inData == callLogItem.payload.data) {
            numDanger += 1;
          }
        }
      }
    }
    return !!numDanger;
  }
}

