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
  TargetProgram::TargetProgram() : state(State(0)), sender(Address(1)), addr(112233){
    gas = ChainParams(genesisInfo(Network::MainNetwork)).maxGasLimit.convert_to<int64_t>();
    gasPrice = 0;
    value = 0;
    nonce = 0;
    blockHeader.setGasLimit(gas);
    blockHeader.setTimestamp(0);
  }
  
  void TargetProgram::warmup() {
    Ethash::init();
    NoProof::init();
  }
  
  ExecutionResult TargetProgram::deployContract(bytes code) {
    bytes data;
    ExecutionResult response;
    Network networkName = Network::MainNetworkTest;
    unique_ptr<SealEngineFace> se(ChainParams(genesisInfo(networkName)).createSealEngine());
    EnvInfo const envInfo(blockHeader, lastBlockHashes, 0);
    Transaction t = Transaction(value, gasPrice, gas, data, nonce);
    executive = new Executive(state, envInfo, *se);
    state.setCode(addr, bytes{code});
    t.forceSender(sender);
    executive->setResultRecipient(response);
    executive->initialize(t);
    executive->call(addr, sender, value, gasPrice, &data, gas);
    executive->go();
    executive->finalize();
    state.setCode(addr, bytes{response.output});
    nonce ++;
    return response;
  }
  
  ExecutionResult TargetProgram::invokeFunction(bytes data) {
    ExecutionResult response;
    Transaction t = Transaction(value, gasPrice, gas, data, nonce);
    t.forceSender(sender);
    executive->setResultRecipient(response);
    executive->initialize(t);
    executive->call(addr, sender, value, gasPrice, &data, gas);
    executive->go();
    executive->finalize();
    return response;
  }
}

