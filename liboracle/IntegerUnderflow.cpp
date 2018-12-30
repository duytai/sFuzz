#include "IntegerUnderflow.h"

namespace fuzzer {
  bool IntegerUnderflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto isUnderflow = callLogItem.payload.isUnderflow;
      if (isUnderflow) return true;
    }
    return false;
  }
}
