#pragma once
#include <iostream>
#include "Common.h"
#include "GaslessSend.h"
#include "ExceptionDisorder.h"
#include "TimestampDependency.h"
#include "BlockNumDependency.h"
#include "DangerDelegateCall.h"
#include "FreezingEther.h"
#include "IntegerUnderflow.h"

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
    IntegerUnderflow integerUnderflow;
    public:
      OracleResult oracleResult;
      OracleFactory();
      void initialize();
      void finalize();
      void save(CallLogItem fc);
      void log(CallLogItem fc);
      void analyze();
  };
}
