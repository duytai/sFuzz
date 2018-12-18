#pragma once
#include <iostream>
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct CallLogItemPayload {
    u256 wei;
    u256 gas;
    Instruction inst;
    bytes data;
    CallLogItemPayload() {
      wei = 0;
      gas = 0;
      data = bytes(0,0);
    }
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
