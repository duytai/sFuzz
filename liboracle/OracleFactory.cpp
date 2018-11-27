#include "OracleFactory.h"
#include "GaslessSend.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer  {
  OracleFactory::OracleFactory() {
    oracleResult.gaslessSend = 0;
  }
  
  void OracleFactory::initialize() {
    callLog.clear();
  }
  
  void OracleFactory::finalize() {
    callLogs.push_back(callLog);
    callLog.clear();
  }
  
  void OracleFactory::save(FunctionCall fc) {
    callLog.push_back(fc);
  }
  
  void OracleFactory::analyze() {
    for (auto callLog : callLogs) {
      oracleResult.gaslessSend += gaslessSend(callLog) ? 1 : 0;
    }
    callLogs.clear();
  }
}
