#include "OracleFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

void OracleFactory::initialize() {
  function.clear();
}

void OracleFactory::finalize() {
  functions.push_back(function);
  function.clear();
}

void OracleFactory::save(OpcodeContext ctx) {
  function.push_back(ctx);
}

vector<bool> OracleFactory::analyze() {
  uint8_t total = 9;
  while (vulnerabilities.size() < total) {
    vulnerabilities.push_back(false);
  }
  for (auto function : functions) {
    for (uint8_t i = 0; i < total; i ++) {
      if (!vulnerabilities[i]) {
        switch (i) {
          case GASLESS_SEND: {
            for (auto ctx: function) {
              auto level = ctx.level;
              auto inst = ctx.payload.inst;
              auto gas = ctx.payload.gas;
              auto data = ctx.payload.data;
              vulnerabilities[i] = vulnerabilities[i] || (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0));
            }
            break;
          }
          case EXCEPTION_DISORDER: {
            auto rootCallResponse = function[function.size() - 1];
            bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
            for (auto ctx : function) {
              vulnerabilities[i] = vulnerabilities[i] || (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level);
            }
            break;
          }
          case TIME_DEPENDENCY: {
            break;
          }
          case NUMBER_DEPENDENCY: {
            break;
          }
          case DELEGATE_CALL: {
            break;
          }
          case REENTRANCY: {
            break;
          }
          case FREEZING: {
            break;
          }
          case UNDERFLOW: {
            for (auto ctx: function) {
              vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isUnderflow;
            }
            break;
          }
          case OVERFLOW: {
            for (auto ctx: function) {
              vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isOverflow;
            }
            break;
          }
        }
      }
    }
  }
  functions.clear();
  return vulnerabilities;
}
