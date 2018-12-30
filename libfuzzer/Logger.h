#pragma once
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class Logger {
    ofstream outfile;
    public:
      Logger() {};
      Logger(string contractName) {
        outfile.open(contractName + "/log.txt", std::ios_base::app);
      };
      void log(string content);
  };
}
