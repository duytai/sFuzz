#include "IntegerUnderflow.h"

namespace fuzzer {
  bool IntegerUnderflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto isUnderflow = callLogItem.payload.isUnderflow;
      if (isUnderflow) {
//        testData = callLogItem.payload.testData;
        return true;
      }
    }
    return false;
  }
}
