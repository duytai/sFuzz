#include "GaslessSend.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool gaslessSend(CallLog callLog) {
    u256 sendGas = 2300;
    u256 numSend = 0;
    for (auto callLogItem : callLog) {
      auto level = callLogItem.level;
      auto inst = callLogItem.payload.inst;
      auto gas = callLogItem.payload.gas;
      if (level > 0 && inst == Instruction::CALL && gas == sendGas) {
        numSend ++;
      }
    }
    return !!numSend;
  }
}

