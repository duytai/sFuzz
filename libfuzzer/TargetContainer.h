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
#include <liboracle/OracleFactory.h>
#include "TargetProgram.h"
#include "ContractABI.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(unordered_set<uint64_t> tracebits, double cksum, unordered_map<uint64_t, double> predicates, unordered_map<string, unordered_set<uint64_t>> uniqExceptions) {
      this->tracebits = tracebits;
      this->cksum = cksum;
      this->predicates = predicates;
      this->uniqExceptions = uniqExceptions;
    }
    /* Contains execution paths */
    unordered_set<uint64_t> tracebits;
    /* Contains checksum of tracebits */
    double cksum;
    /* Save predicates */
    unordered_map<uint64_t, double> predicates;
    unordered_map<string, unordered_set<uint64_t>> uniqExceptions;
  };
  
  class TargetExecutive {
    TargetProgram *program;
    OracleFactory *oracleFactory;
    ContractABI ca;
    bytes code;
    public:
      Address addr;
      TargetExecutive(OracleFactory *oracleFactory, TargetProgram *program, Address addr, ContractABI ca, bytes code) {
        this->code = code;
        this->ca = ca;
        this->addr = addr;
        this->program = program;
        this->oracleFactory = oracleFactory;
      }
      TargetContainerResult exec(bytes data);
      void deploy(bytes data);
  };
  
  class TargetContainer {
    TargetProgram *program;
    OracleFactory *oracleFactory;
    u160 baseAddress;
    public:
      TargetContainer();
      ~TargetContainer();
      void analyze() { oracleFactory->analyze(); }
      OracleResult oracleResult() { return oracleFactory->oracleResult; }
      TargetExecutive loadContract(bytes code, ContractABI ca);
  };
}
