#include "IntegerUnderflow.h"

namespace fuzzer {
  bool IntegerUnderflow::analyze(CallLog callLog) {
    bool isUnderflow = false;
    bool isException = false;
    for (auto callLogItem : callLog) {
      auto inst = callLogItem.payload.inst;
      auto level = callLogItem.level;
      if (!level && inst == Instruction::CALL) {
        if (isUnderflow && !isException) return true;
        isUnderflow = false;
        isException = false;
      }
      if (callLogItem.payload.isUnderflow) {
        testData = callLogItem.payload.testData;
        isUnderflow = true;
      }
      if (inst == Instruction::INVALID) {
        isException = true;
      }
    }
    return isUnderflow && !isException;
  }
}
