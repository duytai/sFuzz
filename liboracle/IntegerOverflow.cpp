#include "IntegerOverflow.h"

namespace fuzzer {
  bool IntegerOverflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto isOverflow = callLogItem.payload.isOverflow;
      if (isOverflow) {
        testData = callLogItem.payload.testData;
        return true;
      }
    }
    return false;
  }
}
