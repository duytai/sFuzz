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
  enum FuzzMode { RANDOM, AFL };
  enum Reporter { TERMINAL, CSV_FILE };
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
    int csvInterval;
    string attackerName;
  };
  struct FuzzStat {
    int idx = 0;
    uint64_t maxdepth = 0;
    uint64_t randomHavoc = 0;
    uint64_t heuristicHavoc = 0;
    bool clearScreen = false;
    int totalExecs = 0;
    int queueCycle = 0;
    int stageFinds[32];
    double lastNewPath = 0;
    int numTest = 0;
    int numException = 0;
    int numJumpis = 0;
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
    unordered_set<uint64_t> tracebits;
    unordered_set<uint64_t> predicates;
    unordered_map<uint64_t, Leader> leaders;
    unordered_map<string, unordered_set<u64>> uniqExceptions;
    Timer timer;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
    void writeStats(Mutation mutation, vector<bool> vulnerabilities);
    ContractInfo mainContract();
    public:
      Fuzzer(FuzzParam fuzzParam);
      bool hasNewExceptions(unordered_map<string, unordered_set<u64>> uniqExceptions);
      FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth);
      void writeTestcase(bytes data, string prefix);
      void writeException(bytes data, string prefix);
      void showStats(Mutation mutation, vector<bool> vulerabilities);
      void updateTracebits(unordered_set<uint64_t> tracebits);
      void updatePredicates(unordered_map<uint64_t, u256> predicates);
      void start();
  };
}
