#pragma once
#include <vector>
#include "LastBlockHashes.h"
#include "ContractABI.h"


using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum ContractCall { CONTRACT_CONSTRUCTOR, CONTRACT_FUNCTION };
  class TargetProgram {
    private:
      State state;
      u256 gas;
      int64_t timestamp;
      int64_t blockNumber;
      u160 sender;
      EnvInfo *envInfo;
      SealEngineFace *se;
      ExecutionResult invoke(Address addr, bytes data, bool payable, OnOpFunc onOp);
    public:
      TargetProgram();
      ~TargetProgram();
      u256 getBalance(Address addr);
      bytes getCode(Address addr);
      map<h256, pair<u256, u256>> storage(Address const& addr);
      void setBalance(Address addr, u256 balance);
      void deploy(Address addr, bytes code);
      void updateEnv(Accounts accounts, FakeBlock block);
      unordered_map<Address, u256> addresses();
      size_t savepoint();
      void rollback(size_t savepoint);
      ExecutionResult invoke(Address addr, ContractCall type, bytes data, bool payable, OnOpFunc onOp);
  };
}
