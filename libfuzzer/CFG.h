#pragma once
#include <iostream>
#include <libdevcore/Common.h>
#include <map>

using namespace std;
using namespace dev;

namespace fuzzer {
  class CFG {
    bytes code;
    bytes codeRuntime;
    unordered_map<int, int> tracebits;
    void simulate(const bytes& code, u256s stack, int pc, int prevLocation, unordered_map<int, int> & prevLocations);
    public:
      int totalCount();
      CFG(string code, string codeRuntime);
  };
}
