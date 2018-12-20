#pragma once
#include <iostream>
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct CallLogItemPayload {
    u256 wei = 0;
    u256 gas = 0;
    u256 pc = 0;
    Instruction inst;
    bytes data;
    bytes code;
    string noted = "";
  };
  struct CallLogItem {
    CallLogItemPayload payload;
    u256 level;
    CallLogItem(u256 _level, CallLogItemPayload _payload): payload(_payload), level(_level) {}
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
