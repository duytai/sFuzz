#pragma once
#include <iostream>
#include <vector>
#include <liboracle/Common.h>
#include "ContractABI.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Mutation.h"
#include "Logger.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum FuzzMode { AFL };
  enum Reporter { TERMINAL, JSON };
  struct ContractInfo {
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
    bool isMain;
  };
  struct FuzzParam {
    vector<ContractInfo> contractInfo;
    FuzzMode mode;
    Reporter reporter;
    int duration;
    int analyzingInterval;
    string attackerName;
  };
  struct FuzzStat {
    int idx = 0;
    uint64_t maxdepth = 0;
    bool clearScreen = false;
    int totalExecs = 0;
    int queueCycle = 0;
    int stageFinds[32];
    double lastNewPath = 0;
  };
  struct Leader {
    FuzzItem item;
    u256 comparisonValue = 0;
    Leader(FuzzItem _item, u256 _comparisionValue): item(_item) {
      comparisonValue = _comparisionValue;
    }
  };
  class Fuzzer {
    Logger logger;
    vector<bool> vulnerabilities;
    unordered_set<uint64_t> tracebits;
    unordered_set<uint64_t> predicates;
    unordered_map<uint64_t, Leader> leaders;
    unordered_set<uint64_t> uniqExceptions;
    Timer timer;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
    void writeStats(const Mutation &mutation);
    ContractInfo mainContract();
    public:
      Fuzzer(FuzzParam fuzzParam);
      FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth);
      void showStats(const Mutation &mutation);
      void updateTracebits(unordered_set<uint64_t> tracebits);
      void updatePredicates(unordered_map<uint64_t, u256> predicates);
      void updateExceptions(unordered_set<uint64_t> uniqExceptions);
      void start();
  };
}
