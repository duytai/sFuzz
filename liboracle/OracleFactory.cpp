#include "OracleFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer  {
  OracleFactory::OracleFactory() {
    remove("contracts/log.txt");
  }
  
  void OracleFactory::initialize() {
    callLog.clear();
  }
  
  void OracleFactory::finalize() {
    callLogs.push_back(callLog);
    callLog.clear();
  }
  
  void OracleFactory::save(CallLogItem fc) {
    callLog.push_back(fc);
  }
  
  void OracleFactory::analyze() {
    for (auto callLog : callLogs) {
      if (!oracleResult.gaslessSend) {
        oracleResult.gaslessSend += gaslessSend.analyze(callLog) ? 1 : 0;
      }
      if (!oracleResult.exceptionDisorder) {
        oracleResult.exceptionDisorder += exceptionDisorder.analyze(callLog) ? 1 : 0;
      }
      if (!oracleResult.timestampDependency) {
        oracleResult.timestampDependency += timestampDependency.analyze(callLog) ? 1 : 0;
      }
      if (!oracleResult.blockNumDependency) {
        oracleResult.blockNumDependency += blockNumberDependency.analyze(callLog) ? 1 : 0;
      }
      if (!oracleResult.dangerDelegateCall) {
        oracleResult.dangerDelegateCall += dangerDelegateCall.analyze(callLog) ? 1 : 0;
      }
      if (!oracleResult.integerOverflow) {
        oracleResult.integerOverflow += integerOverflow.analyze(callLog) ? 1 : 0;
      }
      if (!oracleResult.integerUnderflow) {
        oracleResult.integerUnderflow += integerUnderflow.analyze(callLog) ? 1 : 0;
      }
      if (!oracleResult.freezingEther) {
        oracleResult.freezingEther += freezingEther.analyze(callLog) ? 1 : 0;
      }
    }
    callLogs.clear();
  }
}