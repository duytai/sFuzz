#pragma once
#include <iostream>
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum CallLogItemType { CALL_OPCODE, CALL_EXCEPTION };
  struct CallLogItemPayload {
    u256 wei;
    u256 gas;
    Instruction inst;
  };
  struct CallLogItem {
    CallLogItemType type;
    CallLogItemPayload payload;
    u256 level;
    CallLogItem(CallLogItemType _type, u256 _level): type(_type), level(_level) {}
    CallLogItem(CallLogItemType _type, u256 _level, CallLogItemPayload _payload): type(_type), payload(_payload), level(_level) {}
  };
  
  struct OracleResult {
    u256 gaslessSend;
  };
  
  using CallLogs = vector<vector<CallLogItem>>;
  using CallLog = vector<CallLogItem>;
}
