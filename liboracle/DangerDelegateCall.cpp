#include "DangerDelegateCall.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  bool DangerDelegateCall::analyze(CallLog callLog) {
    auto rootCall = getRootCall(callLog);
    auto data = rootCall.payload.data;
    auto caller = rootCall.payload.caller;
    for (auto callLogItem : callLog) {
      if (callLogItem.payload.inst == Instruction::DELEGATECALL) {
        /* delegatecall(msg.data) */
        if (data == callLogItem.payload.data) {
          testData = rootCall.payload.testData;
          return true;
        };
        /* msg.sender.delegatecall() */
        if (caller == callLogItem.payload.callee) {
          testData = rootCall.payload.testData;
          return true;
        }
        /* msg.data includes(callee address)*/
        if (toHex(data).find(toHex(callLogItem.payload.callee)) != string::npos) {
          testData = rootCall.payload.testData;
          return true;
        }
      }
    }
    return false;
  }
}
