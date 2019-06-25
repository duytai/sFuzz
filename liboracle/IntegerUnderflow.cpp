#include "IntegerUnderflow.h"

namespace fuzzer {
  bool IntegerUnderflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.isUnderflow) {
        testData = callLogItem.payload.testData;
        issuePayloadPc = callLogItem.payload.pc;
        return true;
      }
    }
    return false;
  }
}
