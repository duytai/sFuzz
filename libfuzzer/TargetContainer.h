#pragma once
#include <vector>
#include <map>
#include <liboracle/OracleFactory.h>
#include "Common.h"
#include "TargetProgram.h"
#include "ContractABI.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(
        unordered_set<uint64_t> tracebits,
        unordered_set<uint64_t> branches,
        double cksum,
        unordered_map<uint64_t, u256> predicates,
        unordered_map<string,
        unordered_set<uint64_t>> uniqExceptions,
        map<h256, pair<u256, u256>> storage,
        unordered_map<Address, u256> addresses,
        vector<bytes> outputs
        ) {
      this->tracebits = tracebits;
      this->cksum = cksum;
      this->predicates = predicates;
      this->uniqExceptions = uniqExceptions;
      this->branches = branches;
      this->storage = storage;
      this->addresses = addresses;
      this->outputs = outputs;
    }
    /* Contains execution paths */
    unordered_set<uint64_t> tracebits;
    /* Contains all branches */
    unordered_set<uint64_t> branches;
    /* Contains checksum of tracebits */
    double cksum;
    /* Save predicates */
    unordered_map<uint64_t, u256> predicates;
    /* Exception path */
    unordered_map<string, unordered_set<uint64_t>> uniqExceptions;
    /* Storage */
    map<h256, pair<u256, u256>> storage;
    /* Addresses and balances */
    unordered_map<Address, u256> addresses;
    /* output of function by orders */
    vector<bytes> outputs;
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
      TargetContainerResult exec(bytes data, vector<uint64_t> orders);
      void deploy(bytes data, OnOpFunc onOp);
      static bool storageIsChanged(map<h256, pair<u256, u256>> st1, map<h256, pair<u256, u256>> st2);
  };
  
  class TargetContainer {
    TargetProgram *program;
    OracleFactory *oracleFactory;
    u160 baseAddress;
    public:
      TargetContainer();
      ~TargetContainer();
      vector<tuple<string, bytes, u64>> analyze() { return oracleFactory->analyze(); }
      OracleResult oracleResult() { return oracleFactory->oracleResult; }
      TargetExecutive loadContract(bytes code, ContractABI ca);
  };
}
