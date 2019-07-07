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
    callLog.push_back(fc);
  }
  
  vector<tuple<string, bytes, u64>> OracleFactory::analyze() {
    vector<tuple<string, bytes, u64>> result;
    for (auto callLog : callLogs) {
      if(gaslessSend.analyze(callLog)){
        oracleResult.gaslessSend++;
        result.push_back(make_tuple("gasless_send", gaslessSend.getTestData(), gaslessSend.getPayloadPc()));
      }

      if(exceptionDisorder.analyze(callLog)) {
        oracleResult.exceptionDisorder++;
        result.push_back(make_tuple("exception_disorder", exceptionDisorder.getTestData(), exceptionDisorder.getPayloadPc()));
      }
      if(timestampDependency.analyze(callLog)){
        oracleResult.timestampDependency++;
        result.push_back(make_tuple("timestamp_dependency", timestampDependency.getTestData(), timestampDependency.getPayloadPc()));
      }
      if(blockNumberDependency.analyze(callLog)){
        oracleResult.blockNumDependency++;
        result.push_back(make_tuple("block_number_dependency", blockNumberDependency.getTestData(), blockNumberDependency.getPayloadPc()));
      }
      if(dangerDelegateCall.analyze(callLog)){
        oracleResult.dangerDelegateCall++;
        result.push_back(make_tuple("dangerous_delegatecall", dangerDelegateCall.getTestData(), dangerDelegateCall.getPayloadPc()));
      }
      if(integerOverflow.analyze(callLog)){
        oracleResult.integerOverflow++;
        result.push_back(make_tuple("integer_overflow", integerOverflow.getTestData(), integerOverflow.getPayloadPc()));
      }
      if(integerUnderflow.analyze(callLog)){
        oracleResult.integerUnderflow++;
        result.push_back(make_tuple("integer_underflow", integerUnderflow.getTestData(), integerUnderflow.getPayloadPc()));
      }
      if(reentrancy.analyze(callLog)){
        oracleResult.reentrancy++;
        result.push_back(make_tuple("reentrancy", reentrancy.getTestData(), reentrancy.getPayloadPc()));
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
