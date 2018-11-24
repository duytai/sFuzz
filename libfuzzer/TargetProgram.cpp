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
  TargetProgram::TargetProgram(State& st): state(st) {
    Network networkName = Network::MainNetworkTest;
    LastBlockHashes lastBlockHashes;
    BlockHeader blockHeader;
    s64 maxGasLimit = ChainParams(genesisInfo(networkName))
      .maxGasLimit.convert_to<s64>();
    // add value
    blockHeader.setGasLimit(maxGasLimit);
    blockHeader.setTimestamp(0);
    gas = maxGasLimit;
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
    Address sender(senderAddrValue);
    u256 value = 0;
    u256 gasPrice = 0;
    if (!nonces.count(senderAddrValue)) nonces[senderAddrValue] = 0;
    Transaction t = Transaction(value, gasPrice, gas, data, nonces[senderAddrValue]);
    t.forceSender(sender);
    executive->setResultRecipient(res);
    executive->initialize(t);
    executive->call(addr, sender, value, gasPrice, &data, gas);
    executive->go(onOp);
    executive->finalize();
    nonces[senderAddrValue] ++;
    return res;
  }

  void TargetProgram::updateEnv(ContractEnv env) {
    unordered_set<string> accountSet; // to check exists
    auto accounts = env.accounts;
    accounts.push_back(env.sender);
    for (auto account : accounts) {
      /* 8 bytes - 4 bytes (balance) - 20 bytes (address) */
      bytes balance(account.begin(), account.begin() + 12);
      bytes addr(account.begin() + 12, account.end());
      u256 balanceValue = u256("0x" + toHex(balance));
      auto pair = accountSet.insert(toString(addr));
      if (pair.second) state.setBalance(Address(addr), balanceValue);
    }
    senderAddrValue = u160("0x" + toHex(bytes(env.sender.begin() + 12, env.sender.end())));
  }
  
  TargetProgram::~TargetProgram() {
    delete executive;
  }
}

