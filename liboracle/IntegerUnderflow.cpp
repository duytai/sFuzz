#include "IntegerUnderflow.h"

namespace fuzzer {
  bool IntegerUnderflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.isUnderflow) {
        testData = callLogItem.payload.testData;
        return true;
      }
    }
    return false;
  }
}
