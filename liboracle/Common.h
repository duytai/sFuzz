#pragma once
#include <iostream>
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum CallLogItemType {
    CALL_OPCODE,
    CALL_EXCEPTION,
    TIMESTAMP_OPCODE,
    NUMBER_OPCODE,
    SUICIDE_OPCODE,
  };
  struct CallLogItemPayload {
    u256 wei;
    u256 gas;
    Instruction inst;
    bytes data;
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
    u256 exceptionDisorder;
    u256 timestampDependency;
    u256 blockNumDependency;
    u256 dangerDelegateCall;
    u256 reentrancy;
    u256 freezingEther;
  };
  
  using CallLogs = vector<vector<CallLogItem>>;
  using CallLog = vector<CallLogItem>;
}
