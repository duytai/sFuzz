#include "IntegerUnderflow.h"

namespace fuzzer {
  bool IntegerUnderflow::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.isUnderflow) {
        return true;
      }
    }
    return false;
  }
}
