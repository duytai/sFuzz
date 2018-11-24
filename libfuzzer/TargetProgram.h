#pragma once
#include <iostream>
#include <vector>
#include <libdevcore/CommonIO.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethashseal/GenesisInfo.h>
#include <libethereum/LastBlockHashesFace.h>
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
      u160 senderAddrValue;
      unordered_map<u160, u256> nonces;
      Executive *executive;
      ExecutionResult invoke(Address addr, bytes data, OnOpFunc onOp);
    public:
      TargetProgram(State& state);
      ~TargetProgram();
      void deploy(Address addr, bytes code);
      void updateEnv(ContractEnv env);
      ExecutionResult invoke(Address addr, ContractCall type, bytes data, OnOpFunc onOp);
  };
}
