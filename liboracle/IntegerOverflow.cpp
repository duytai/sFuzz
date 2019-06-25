#include "IntegerOverflow.h"

namespace fuzzer {
  bool IntegerOverflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.isOverflow) {
        testData = callLogItem.payload.testData;
        issuePayloadPc = callLogItem.payload.pc;
        return true;
      }
    }
    return false;
  }
}
