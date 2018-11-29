#include <libdevcore/CommonIO.h>
#include <libdevcore/SHA3.h>
#include <libethashseal/Ethash.h>
#include <libethashseal/GenesisInfo.h>
#include <libethcore/SealEngine.h>
#include <libethereum/Block.h>
#include <libethereum/ChainParams.h>
#include <libethereum/Executive.h>
#include <libethereum/LastBlockHashesFace.h>
#include <libevm/VMFactory.h>
#include "TargetProgram.h"
#include "Util.h"

using namespace dev;
using namespace eth;


namespace fuzzer {
  TargetProgram::TargetProgram(): state(State(0)) {
    Network networkName = Network::MainNetworkTest;
    LastBlockHashes lastBlockHashes;
    BlockHeader blockHeader;
    s64 maxGasLimit = ChainParams(genesisInfo(networkName))
      .maxGasLimit.convert_to<s64>();
    // add value
    blockHeader.setGasLimit(maxGasLimit);
    blockHeader.setTimestamp(0);
    blockHeader.setNumber(2675000);
    gas = MAX_GAS;
    Ethash::init();
    NoProof::init();
    SealEngineFace *se = ChainParams(genesisInfo(networkName)).createSealEngine();
    EnvInfo envInfo(blockHeader, lastBlockHashes, 0);
    executive = new Executive(state, envInfo, *se);
  }

  void TargetProgram::deploy(Address addr, bytes code) {
    state.clearStorage(addr);
    state.setCode(addr, bytes{code});
  }
  
  ExecutionResult TargetProgram::invoke(Address addr, ContractCall type, bytes data, OnOpFunc onOp) {
    switch (type) {
      case CONTRACT_CONSTRUCTOR: {
        bytes code = state.code(addr);
        code.insert(code.end(), data.begin(), data.end());
        state.setCode(addr, bytes{code});
        ExecutionResult res = invoke(addr, data, onOp);
        state.setCode(addr, bytes{res.output});
        return res;
      }
      case CONTRACT_FUNCTION: {
        return invoke(addr, data, onOp);
      }
      default: {
        throw "Unknown invoke type";
      }
    }
  }
  
  ExecutionResult TargetProgram::invoke(Address addr, bytes data, OnOpFunc onOp) {
    ExecutionResult res;
    Address senderAddr(sender);
    u256 value = 0;
    u256 gasPrice = 0;
    if (!nonces.count(sender)) nonces[sender] = 0;
    Transaction t = Transaction(value, gasPrice, gas, data, nonces[sender]);
    t.forceSender(senderAddr);
    executive->setResultRecipient(res);
    executive->initialize(t);
    executive->call(addr, senderAddr, value, gasPrice, &data, gas);
    executive->go(onOp);
    executive->finalize();
    nonces[sender] ++;
    return res;
  }

  void TargetProgram::updateEnv(Accounts accounts) {
    for (auto account: accounts) {
      auto address = get<1>(account);
      auto balance = get<2>(account);
      auto isSender = get<3>(account);
      state.setBalance(Address(address), balance);
      if (isSender) sender = address;
    }
  }
  
  TargetProgram::~TargetProgram() {
    delete executive;
  }
}

