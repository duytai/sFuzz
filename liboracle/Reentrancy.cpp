#include "Reentrancy.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool Reentrancy::analyze(CallLog callLog) {
    uint pos = 0;
    bool ret = false;
    for(uint i = 0; i < callLog.size(); i++) {
      auto callLogItem = callLog[i];
      auto data = callLogItem.payload.data;
      auto level = callLogItem.level;
      if (level >= 4 && toHex(data) == "000000ff") {
        testData = callLog[0].payload.testData;
        pos = i;
        ret = true;
        break;
      }
    }
    if(pos > 0) {
      for (uint i = pos - 1; i > 0; --i)
      {
         auto callLogItem = callLog[i];
         if (callLogItem.level == 1) {
            issuePayloadPc = callLogItem.payload.pc;
            break;
         }
      }
    }
    return ret;
  }
}

