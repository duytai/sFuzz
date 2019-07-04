#include "IntegerOverflow.h"

namespace fuzzer {
  bool IntegerOverflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.isOverflow) {
        return true;
      }
    }
    return false;
  }
}
