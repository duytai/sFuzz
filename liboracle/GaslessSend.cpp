#include "GaslessSend.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool GaslessSend::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto level = callLogItem.level;
      auto inst = callLogItem.payload.inst;
      auto gas = callLogItem.payload.gas;
      if (level > 0 && inst == Instruction::CALL && gas == 2300) {
        numSend ++;
      }
    }
    return !!numSend;
  }
}

