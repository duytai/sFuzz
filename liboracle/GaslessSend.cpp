#include "GaslessSend.h"

using namespace dev;
using namespace eth;
using namespace std;
/*
 * .transfer() toHex(callLogItem.payload.code) != "93505050501580156092573d"
 */
namespace fuzzer {
  bool GaslessSend::analyze(CallLog callLog) {
    for (auto callLogItem : callLog) {
      auto level = callLogItem.level;
      auto inst = callLogItem.payload.inst;
      auto gas = callLogItem.payload.gas;
      auto data = callLogItem.payload.data;
      if (
        level == 1 &&
        inst == Instruction::CALL &&
        !data.size() &&
        (gas == 2300 || gas == 0)
      ) {
        numSend ++;
//        if (!testData.size()) testData = callLogItem.payload.testData;
      }
    }
    return !!numSend;
  }
}

