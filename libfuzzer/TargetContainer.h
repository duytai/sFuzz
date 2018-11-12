#pragma once
#include <iostream>
#include <vector>
#include <map>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>
#include "TargetProgram.h"
#include "ContractABI.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(bytes tracebits, h256 cksum, double exTime, unordered_map<uint64_t, double> predicates) {
      this->tracebits = tracebits;
      this->cksum = cksum;
      this->exTime = exTime;
      this->predicates = predicates;
    }
    /* Contains execution paths */
    bytes tracebits;
    /* Contains checksum of tracebits */
    h256 cksum;
    /* Execution time */
    double exTime;
    /* Save predicates */
    unordered_map<uint64_t, double> predicates;
  };
  
  class TargetContainer {
    bytes code;
    ContractABI ca;
    TargetProgram program;
    public:
      TargetContainer(bytes code, ContractABI ca);
      TargetContainerResult exec(bytes data);
  };
}
