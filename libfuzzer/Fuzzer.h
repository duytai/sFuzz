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
  class Fuzzer {
    ContractABI ca;
    bytes code;
    bytes virginbits;
    TargetContainer container;
    vector<FuzzItem> queues;
    unordered_set<u64> uniqExceptions;
    unordered_set<string> typeExceptions;
    int idx;
    int maxdepth;
    bool clearScreen;
    int totalExecs;
    int queueCycle;
    int stageFinds[32];
    int coveredTuples;
    double lastNewPath;
    Timer timer;
    CFG cfg;
    public:
      Fuzzer(bytes code , ContractABI ca, CFG cfg);
      u8 hasNewBits(bytes tracebits);
      FuzzItem saveIfInterest(bytes data, int depth);
      void start();
      void showStats(Mutation mutation, FuzzItem item);
  };
}
