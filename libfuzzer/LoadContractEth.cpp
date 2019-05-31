#include "LoadContractEth.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "Logger.h"


using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
using namespace dev::eth;

namespace fuzzer {
    TargetExecutive LoadContractEth::loadContractfromEthereum(std::string name, std::string address, vector<ContractInfo> contractInfo) {
        ContractInfo contract;
        //search for contractAbi
        for (auto i : contractInfo) {
            if (name == i.contractName)
                contract = i;
        }
        // from address get bytecode
        ChainParams chainParams;
        chainParams = ChainParams(
            genesisInfo(eth::Network::MainNetwork), genesisStateRoot(eth::Network::MainNetwork));

        dev::WebThreeDirect web3(WebThreeDirect::composeClientVersion("eth"), "", "", chainParams,
            WithExisting::Kill, set<string>{"eth"});


        std::string bin =
            toJS(web3.ethereum()->codeAt(jsToAddress(address), jsToBlockNumber("pending")));
 
        return loadContract(bin, contract.abiJson);

    }

    //load contract with bin and json
    TargetExecutive LoadContractEth::loadContract(std::string _bin, std::string json) {
        TargetContainer container;
        ContractABI ca(json);
        auto bin = fromHex(_bin);
        TargetExecutive executive = container.loadContract(bin, ca);
        return executive;
    }

}
