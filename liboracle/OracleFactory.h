#pragma once
#include <iostream>

#include "Common.h"
#include "GaslessSend.h"
#include "ExceptionDisorder.h"
#include "TimestampDependency.h"
#include "BlockNumDependency.h"
#include "DangerDelegateCall.h"
#include "FreezingEther.h"
#include "IntegerOverflow.h"
#include "IntegerUnderflow.h"
#include "Reentrancy.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  
  class OracleFactory {
    CallLog callLog;
    CallLogs callLogs;
    TimestampDependency timestampDependency;
    BlockNumberDependency blockNumberDependency;
    GaslessSend gaslessSend;
    ExceptionDisorder exceptionDisorder;
    DangerDelegateCall dangerDelegateCall;
    FreezingEther freezingEther;
    IntegerOverflow integerOverflow;
    IntegerUnderflow integerUnderflow;
    Reentrancy reentrancy;
    public:
      OracleResult oracleResult;
      OracleFactory();
      void initialize();
      void finalize(bool storageChanged);
      void save(CallLogItem fc);
      vector<tuple<string, bytes, u64>> analyze();
  };
}
