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
  
  void OracleFactory::finalize(bool storageChanged) {
    callLog[0].payload.storageChanged = storageChanged;
    callLogs.push_back(callLog);
    callLog.clear();
  }
  
  void OracleFactory::save(CallLogItem fc) {
    ofstream test("x.txt", ios::app);
    test << "pc:" <<fc.payload.pc<<endl;
    test << "inst:" <<(int)fc.payload.inst<<endl;
    test << "data:" << fc.payload.data<<endl;
    test << "testdata:" << fc.payload.testData<<endl;
    test.close();
    callLog.push_back(fc);
  }
  
  vector<tuple<string, bytes, u64>> OracleFactory::analyze() {
    vector<tuple<string, bytes, u64>> result;
    for (auto callLog : callLogs) {
      if (!oracleResult.gaslessSend) {
        oracleResult.gaslessSend += gaslessSend.analyze(callLog) ? 1 : 0;
        if (oracleResult.gaslessSend) {
          result.push_back(make_tuple("gasless_send", gaslessSend.getTestData(), gaslessSend.getPayloadPc()));
        }
      }
      if (!oracleResult.exceptionDisorder) {
        oracleResult.exceptionDisorder += exceptionDisorder.analyze(callLog) ? 1 : 0;
        if (oracleResult.exceptionDisorder) {
          result.push_back(make_tuple("exception_disorder", exceptionDisorder.getTestData(), exceptionDisorder.getPayloadPc()));
        }
      }
      if (!oracleResult.timestampDependency) {
        oracleResult.timestampDependency += timestampDependency.analyze(callLog) ? 1 : 0;
        if (oracleResult.timestampDependency) {
          result.push_back(make_tuple("timestamp_dependency", timestampDependency.getTestData(), timestampDependency.getPayloadPc()));
        }
      }
      if (!oracleResult.blockNumDependency) {
        oracleResult.blockNumDependency += blockNumberDependency.analyze(callLog) ? 1 : 0;
        if (oracleResult.blockNumDependency) {
          result.push_back(make_tuple("block_number_dependency", blockNumberDependency.getTestData(), blockNumberDependency.getPayloadPc()));
        }
      }
      if (!oracleResult.dangerDelegateCall) {
        oracleResult.dangerDelegateCall += dangerDelegateCall.analyze(callLog) ? 1 : 0;
        if (oracleResult.dangerDelegateCall) {
          result.push_back(make_tuple("dangerous_delegatecall", dangerDelegateCall.getTestData(), dangerDelegateCall.getPayloadPc()));
        }
      }
      if (!oracleResult.integerOverflow) {
        oracleResult.integerOverflow += integerOverflow.analyze(callLog) ? 1 : 0;
        if (oracleResult.integerOverflow) {
          result.push_back(make_tuple("integer_overflow", integerOverflow.getTestData(), integerOverflow.getPayloadPc()));
        }
      }
      if (!oracleResult.integerUnderflow) {
        oracleResult.integerUnderflow += integerUnderflow.analyze(callLog) ? 1 : 0;
        if (oracleResult.integerUnderflow) {
          result.push_back(make_tuple("integer_underflow", integerUnderflow.getTestData(), integerUnderflow.getPayloadPc()));
        }
      }
      if (!oracleResult.reentrancy) {
        oracleResult.reentrancy += reentrancy.analyze(callLog) ? 1 : 0;
        if (oracleResult.reentrancy) {
          result.push_back(make_tuple("reentrancy", reentrancy.getTestData(), reentrancy.getPayloadPc()));
        }
      }
      if (!oracleResult.freezingEther) {
        freezingEther.analyze(callLog);
      }
    }
    if (freezingEther.isFreezed()) {
      oracleResult.freezingEther = 1;
      result.push_back(make_tuple("freezing_ether", freezingEther.getTestData(),freezingEther.getPayloadPc()));
    }
    callLogs.clear();
    return result;
  }
}
