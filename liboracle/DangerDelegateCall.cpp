#include "DangerDelegateCall.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool DangerDelegateCall::analyze(CallLog callLog, bytes) {
    bytes inData;
    for (auto callLogItem : callLog) {
      auto level = callLogItem.level;
      auto inst = callLogItem.payload.inst;
      auto data = callLogItem.payload.data;
      if (level == 0 && inst == Instruction::CALL) {
        inData = callLogItem.payload.data;
      }
      if (level > 0 && inst == Instruction::DELEGATECALL && inData == data) {
        numDanger ++;
      }
    }
    return !!numDanger;
  }
}
