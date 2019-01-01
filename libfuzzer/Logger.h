#pragma once
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class Logger {
    uint64_t counter = 0;
    stringstream data;
    string contractName;
    public:
      Logger(string _contractName) {
        contractName = _contractName;
      };
      void writeOut(bool isInteresting);
      void log(string content);
      void clear();
  };
}
