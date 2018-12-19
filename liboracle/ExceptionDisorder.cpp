#include "ExceptionDisorder.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool exceptionDisorder(CallLog callLog) {
    bool rootException = false;
    bool nestedException = false;
    u256 numDisorder = 0;
    
    for (auto callLogItem : callLog) {
      auto level = callLogItem.level;
      auto inst = callLogItem.payload.inst;
      if (level == 0) {
        if (inst == Instruction::CALL) {
          if (!rootException && nestedException) numDisorder ++;
          rootException = nestedException = false;
        }
        if (inst == Instruction::INVALID) {
          rootException = true;
        }
      } else if (inst == Instruction::INVALID) {
        nestedException = true;
      }
    }
    numDisorder += (!rootException && nestedException);
    return !!numDisorder;
  }
}

