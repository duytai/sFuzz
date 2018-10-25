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

using namespace dev;
using namespace eth;


namespace fuzzer {
  TargetProgram::TargetProgram(): state(State(0)), sender(Address(69)), contractAddress(Address(100)) {
    Network networkName = Network::MainNetworkTest;
    LastBlockHashes lastBlockHashes;
    BlockHeader blockHeader;
    int64_t maxGasLimit = ChainParams(genesisInfo(networkName))
      .maxGasLimit.convert_to<int64_t>();
    // add value
    blockHeader.setGasLimit(maxGasLimit);
    blockHeader.setTimestamp(0);
    gas = maxGasLimit;
    Ethash::init();
    NoProof::init();
    se = ChainParams(genesisInfo(networkName)).createSealEngine();
    envInfo = new EnvInfo(blockHeader, lastBlockHashes, 0);
    nonce = 0;
  }

  void TargetProgram::deploy(bytes code) {
    state.setCode(contractAddress, bytes{code});
  }
  
  ExecutionResult TargetProgram::invokeFunction(bytes data) {
    return invoke(data);
  }
  
  ExecutionResult TargetProgram::invokeConstructor(bytes data) {
    bytes code = state.code(contractAddress);
    code.insert(code.end(), data.begin(), data.end());
    state.setCode(contractAddress, bytes{code});
    ExecutionResult res = invoke(data);
    state.setCode(contractAddress, bytes{res.output});
    return res;
  }
  
  ExecutionResult TargetProgram::invoke(bytes data) {
    ExecutionResult res;
    u256 value = 0;
    u256 gasPrice = 0;
    Transaction t = Transaction(value, gasPrice, gas, data, nonce);
    t.forceSender(sender);
    Executive executive(state, *envInfo, *se);
    executive.setResultRecipient(res);
    executive.initialize(t);
    executive.call(contractAddress, sender, value, gasPrice, &data, gas);
    executive.go();
    executive.finalize();
    nonce ++;
    return res;
  }
  
  TargetProgram::~TargetProgram() {
    delete se;
    delete envInfo;
  }
}

