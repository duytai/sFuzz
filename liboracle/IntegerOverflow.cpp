#include "IntegerOverflow.h"

namespace fuzzer {
  bool IntegerOverflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto isOverflow = callLogItem.payload.isOverflow;
      if (isOverflow) return true;
    }
    return false;
  }
}
