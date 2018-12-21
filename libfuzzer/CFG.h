#pragma once
#include <map>
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct OpStat {
    vector<uint64_t> pcs;
    vector<uint64_t> jumpdests;
  };
  struct CFGStat {
    map<uint64_t, u256> pcs;
    map<uint64_t, u256> jumpdests;
  };
  class CFG {
    string bin;
    vector<u256> lines;
    void simulate(bytes bin, vector<u256> stack, uint64_t pc, CFGStat& cfgStat);
    public:
      CFG(bytes code);
      static OpStat staticAnalyze(bytes bin);
      static CFGStat toCFGStat(OpStat opStat);
  };
}
