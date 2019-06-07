#include "LoadContractEth.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "Logger.h"

using namespace std;
using namespace fuzzer;
using namespace jsonrpc;

namespace fuzzer {
    TargetExecutive LoadContractEth::loadContractfromEthereum(std::string name, std::string address, vector<ContractInfo> contractInfo) {
        ContractInfo contract;
        //search for contractAbi
        for (auto i : contractInfo) {
            if (name == i.contractName)
                contract = i;
        }
        // from address get bytecode

        std::string bin = getBinaryCode(address);
 
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

    string LoadContractEth::getBinaryCode(string address) {
        HttpClient client("https://mainnet.infura.io");
        jsonrpc::Client c(client);

        Json::Value params;
        params["DATA"] = address;
        params["TAG"] = "pending";

        Json::Value result = c.CallMethod("eth_getCode", params);

        return result["result"].asString();
    }

}
