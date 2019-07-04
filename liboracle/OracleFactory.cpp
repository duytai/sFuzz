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
      switch (i) {
        case GASLESS_SEND: {}
        case EXCEPTION_DISORDER: {}
        case TIME_DEPENDENCY: {}
        case NUMBER_DEPENDENCY: {}
        case DELEGATE_CALL: {}
        case REENTRANCY: {}
        case FREEZING: {}
        case UNDERFLOW: {}
        case OVERFLOW: {}
      }
    }
  }
  functions.clear();
  return vulnerabilities;
}
