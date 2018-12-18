#include "BlockNumDependency.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool blockNumDependency(CallLog callLog) {
    u256 numBlocknumber = 0;
    u256 numSend = 0;
    for (auto callLogItem : callLog) {
      auto level = callLogItem.level;
      auto inst = callLogItem.payload.inst;
      if (level > 0) {
        if (inst == Instruction::NUMBER) numBlocknumber ++;
        if (inst == Instruction::CALL) numSend ++;
      }
    }
    return !!numBlocknumber && !!numSend;
  }
}

