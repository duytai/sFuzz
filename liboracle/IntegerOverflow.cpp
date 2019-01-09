#include "IntegerOverflow.h"

namespace fuzzer {
  bool IntegerOverflow::analyze(CallLog callLog) {
    bool isOverflow = false;
    bool isException = false;
    for (auto callLogItem : callLog) {
      auto inst = callLogItem.payload.inst;
      auto level = callLogItem.level;
      if (!level && inst == Instruction::CALL) {
        if (isOverflow && !isException) return true;
        isOverflow = false;
        isException = false;
      }
      if (callLogItem.payload.isOverflow) {
        testData = callLogItem.payload.testData;
        isOverflow = true;
      }
      if (inst == Instruction::INVALID) {
        isException = true;
      }
    }
    return isOverflow && !isException;
  }
}
