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
      auto data = callLogItem.payload.data;
      if (
        level > 0 &&
        inst == Instruction::CALL &&
        !data.size() &&
        (gas == 2300 || gas == 0)
      ) {
        numSend ++;
      }
    }
    return !!numSend;
  }
}

