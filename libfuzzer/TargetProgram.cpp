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
    gas = MAX_GAS;
    timestamp = 0;
    blockNumber = 2675000;
    Ethash::init();
    NoProof::init();
    se = ChainParams(genesisInfo(networkName)).createSealEngine();
    // add value
    blockHeader.setGasLimit(maxGasLimit);
    blockHeader.setTimestamp(timestamp);
    blockHeader.setNumber(blockNumber);
    envInfo = new EnvInfo(blockHeader, lastBlockHashes, 0);
  }
  
  void TargetProgram::setBalance(Address addr, u256 balance) {
    state.setBalance(addr, balance);
  }
    
  u256 TargetProgram::getBalance(Address addr) {
    return state.balance(addr);
  }

  void TargetProgram::deploy(Address addr, bytes code) {
    state.clearStorage(addr);
    state.setCode(addr, bytes{code});
  }
    
  bytes TargetProgram::getCode(Address addr) {
    return state.code(addr);
  }
  
  ExecutionResult TargetProgram::invoke(Address addr, ContractCall type, bytes data, bool payable, OnOpFunc onOp) {
    switch (type) {
      case CONTRACT_CONSTRUCTOR: {
        bytes code = state.code(addr);
        code.insert(code.end(), data.begin(), data.end());
        state.setCode(addr, bytes{code});
        ExecutionResult res = invoke(addr, data, payable, onOp);
        state.setCode(addr, bytes{res.output});
        return res;
      }
      case CONTRACT_FUNCTION: {
        return invoke(addr, data, payable, onOp);
      }
      default: {
        throw "Unknown invoke type";
      }
    }
  }
  
  ExecutionResult TargetProgram::invoke(Address addr, bytes data, bool payable, OnOpFunc onOp) {
    ExecutionResult res;
    Address senderAddr(sender);
    u256 value = payable ? state.balance(sender) / 2 : 0;
    u256 gasPrice = 0;
    Transaction t = Transaction(value, gasPrice, gas, data, state.getNonce(sender));
    t.forceSender(senderAddr);
    Executive executive(state, *envInfo, *se);
    executive.setResultRecipient(res);
    executive.initialize(t);
    LegacyVM::payload = data;
    executive.call(addr, senderAddr, value, gasPrice, &data, gas);
    executive.updateBlock(blockNumber, timestamp);
    executive.go(onOp);
    executive.finalize();
    return res;
  }

  void TargetProgram::updateEnv(Accounts accounts, FakeBlock block) {
    for (auto account: accounts) {
      auto address = get<1>(account);
      auto balance = get<2>(account);
      auto isSender = get<3>(account);
      state.setBalance(Address(address), balance);
      if (isSender) sender = address;
    }
    blockNumber = get<1>(block);
    timestamp = get<2>(block);
  }

  void TargetProgram::rollback(size_t savepoint) {
    state.rollback(savepoint);
  }

  size_t TargetProgram::savepoint() {
    return state.savepoint();
  }
  
  TargetProgram::~TargetProgram() {
    delete envInfo;
    delete se;
  }
}

