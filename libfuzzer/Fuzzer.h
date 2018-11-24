#pragma once
#include <iostream>
#include <vector>
#include <functional>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>
#include "ContractABI.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Mutation.h"
#include "CFG.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum FuzzMode { RANDOM, AFL };
  struct ContractInfo {
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
  };
  struct FuzzParam {
    ContractInfo fuzzContract;
    vector<ContractInfo> assetContracts;
    FuzzMode mode;
    int duration;
  };
  struct FuzzStat {
    int idx;
    int maxdepth;
    bool clearScreen;
    int totalExecs;
    int queueCycle;
    int stageFinds[32];
    int coveredTuples;
    double lastNewPath;
    int numTest;
    int numException;
  };
  class Fuzzer {
    unordered_set<uint64_t> tracebits;
    vector<FuzzItem> queues;
    unordered_map<string, unordered_set<u64>> uniqExceptions;
    Timer timer;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
    void writeStats(Mutation mutation, CFG cfg);
    public:
      Fuzzer(FuzzParam fuzzParam);
      u8 hasNewBits(unordered_set<uint64_t> tracebits);
      u8 hasNewExceptions(unordered_map<string, unordered_set<u64>> uniqExceptions);
      FuzzItem saveIfInterest(TargetContainer& container, bytes data, int depth);
      void start();
      void writeTestcase(bytes data);
      void writeException(bytes data);
      void showStats(Mutation mutation, CFG cfg);
  };
}
