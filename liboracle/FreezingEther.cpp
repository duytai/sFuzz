#include "FreezingEther.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool freezingEther(CallLog callLog) {
    u256 numTransfer = 0;
    u256 numDelegatecall = 0;
    for (auto callLogItem : callLog) {
      auto inst = callLogItem.payload.inst;
      auto level = callLogItem.level;
      if (level > 0) {
        if (inst == Instruction::DELEGATECALL) numDelegatecall += 1;
        if (level == 1 && (inst == Instruction::CALL || inst == Instruction::SUICIDE)) {
          numTransfer ++;
        }
      }
    }
    return !numTransfer && !!numDelegatecall;
  }
}

