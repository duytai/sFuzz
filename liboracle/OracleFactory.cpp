#include "OracleFactory.h"
#include "GaslessSend.h"
#include "ExceptionDisorder.h"
#include "TimestampDependency.h"
#include "BlockNumDependency.h"
#include "DangerDelegateCall.h"
#include "Reentrancy.h"
#include "FreezingEther.h"

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
  
  void OracleFactory::log(CallLogItem fc) {
    /* Write to log files */
    return;
    stringstream outfile;
    outfile << fc.level << ",";
    outfile << instructionInfo(fc.payload.inst).name << ",";
    outfile << fc.payload.gas << ",";
    outfile << fc.payload.wei << ",";
    outfile << toHex(fc.payload.data) << ",";
    outfile << fc.payload.noted << endl;
    cout << outfile.str();
  }
  
  void OracleFactory::analyze() {
    for (auto callLog : callLogs) {
      if (!oracleResult.gaslessSend)
        oracleResult.gaslessSend += gaslessSend(callLog) ? 1 : 0;
      if (!oracleResult.exceptionDisorder)
        oracleResult.exceptionDisorder += exceptionDisorder(callLog) ? 1 : 0;
      if (!oracleResult.timestampDependency)
        oracleResult.timestampDependency += timestampDependency(callLog) ? 1 : 0;
      if (!oracleResult.blockNumDependency)
        oracleResult.blockNumDependency += blockNumDependency(callLog) ? 1 : 0;
      if (!oracleResult.dangerDelegateCall)
        oracleResult.dangerDelegateCall += dangerDelegateCall(callLog) ? 1 : 0;
      /*
       * if (!oracleResult.reentrancy)
       * oracleResult.reentrancy += reentrancy(callLog) ? 1 : 0;
       */
      if (!oracleResult.freezingEther) {
        oracleResult.freezingEther += freezingEther(callLog);
      }
    }
    callLogs.clear();
  }
}
