#pragma once
#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  
  class OracleFactory {
    CallLog callLog;
    CallLogs callLogs;
    bool hasTranfer;
    public:
      OracleResult oracleResult;
      OracleFactory();
      void initialize();
      void finalize();
      void save(CallLogItem fc);
      void analyze();
  };
}
