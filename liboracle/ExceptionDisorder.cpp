#include "ExceptionDisorder.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool ExceptionDisorder::analyze(CallLog callLog) {
    auto rootCallResponse = callLog[callLog.size() - 1];
    bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
    uint pos = 0;
    bool ret = false;
    for (uint i = 0; i < callLog.size(); ++i) {
      auto callLogItem = callLog[i];
      if (!rootException && callLogItem.payload.inst == Instruction::INVALID && callLogItem.level) {
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
