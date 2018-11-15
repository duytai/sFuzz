#pragma once
#include <iostream>
#include <libdevcore/Common.h>
#include <libevm/Instruction.h>
#include <map>

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  class CFG {
    bytes code;
    bytes codeRuntime;
    unordered_map<int, int> tracebits;
    unordered_set<int> jumpdests;
    unordered_set<int> jumpis;
    unordered_set<int> findops(const bytes& code, Instruction op);
    void simulate(const bytes& code, u256s stack, int pc, int prevLocation, unordered_set<int>& prevLocations);
    public:
      int totalCount();
      int extraEstimation;
      CFG(string code, string codeRuntime);
  };
}
