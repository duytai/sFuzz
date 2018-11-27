#pragma once
#include <iostream>
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct FunctionCall {
    u256 depth;
    u256 wei;
    u256 gas;
    Instruction inst;
  };
  
  struct OracleResult {
    u256 gaslessSend;
  };
  
  using CallLogs = vector<vector<FunctionCall>>;
  using CallLog = vector<FunctionCall>;
}
