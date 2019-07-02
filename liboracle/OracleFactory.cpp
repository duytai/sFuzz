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
  
  vector<tuple<string, bytes>> OracleFactory::analyze() {
    vector<tuple<string, bytes>> result;
    for (auto callLog : callLogs) {
      if (!oracleResult.gaslessSend) {
        oracleResult.gaslessSend += gaslessSend.analyze(callLog) ? 1 : 0;
        if (oracleResult.gaslessSend) {
          result.push_back(make_tuple("gasless_send", gaslessSend.getTestData()));
        }
      }
      if (!oracleResult.exceptionDisorder) {
        oracleResult.exceptionDisorder += exceptionDisorder.analyze(callLog) ? 1 : 0;
        if (oracleResult.exceptionDisorder) {
          result.push_back(make_tuple("exception_disorder", exceptionDisorder.getTestData()));
        }
      }
      if (!oracleResult.timestampDependency) {
        oracleResult.timestampDependency += timestampDependency.analyze(callLog) ? 1 : 0;
        if (oracleResult.timestampDependency) {
          result.push_back(make_tuple("timestamp_dependency", timestampDependency.getTestData()));
        }
      }
      if (!oracleResult.blockNumDependency) {
        oracleResult.blockNumDependency += blockNumberDependency.analyze(callLog) ? 1 : 0;
        if (oracleResult.blockNumDependency) {
          result.push_back(make_tuple("block_number_dependency", blockNumberDependency.getTestData()));
        }
      }
      if (!oracleResult.dangerDelegateCall) {
        oracleResult.dangerDelegateCall += dangerDelegateCall.analyze(callLog) ? 1 : 0;
        if (oracleResult.dangerDelegateCall) {
          result.push_back(make_tuple("dangerous_delegatecall", dangerDelegateCall.getTestData()));
        }
      }
      if (!oracleResult.integerOverflow) {
        oracleResult.integerOverflow += integerOverflow.analyze(callLog) ? 1 : 0;
        if (oracleResult.integerOverflow) {
          result.push_back(make_tuple("integer_overflow", integerOverflow.getTestData()));
        }
      }
      if (!oracleResult.integerUnderflow) {
        oracleResult.integerUnderflow += integerUnderflow.analyze(callLog) ? 1 : 0;
        if (oracleResult.integerUnderflow) {
          result.push_back(make_tuple("integer_underflow", integerUnderflow.getTestData()));
        }
      }
      if (!oracleResult.reentrancy) {
        oracleResult.reentrancy += reentrancy.analyze(callLog) ? 1 : 0;
        if (oracleResult.reentrancy) {
          result.push_back(make_tuple("reentrancy", reentrancy.getTestData()));
        }
      }
      if (!oracleResult.freezingEther) {
        freezingEther.analyze(callLog);
      }
    }
    if (freezingEther.isFreezed()) {
      oracleResult.freezingEther = 1;
      result.push_back(make_tuple("freezing_ether", freezingEther.getTestData()));
    }
    callLogs.clear();
    return result;
  }
}
