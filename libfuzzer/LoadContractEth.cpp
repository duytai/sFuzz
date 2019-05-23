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
using json = nlohmann::json;

namespace fuzzer {
    TargetExecutive LoadContractEth::loadContractfromEthereum(string name, string address, vector<ContractInfo> contractInfo) {
        ContractInfo contract;
        //search for contractAbi
        for (auto i : contractInfo) {
            if (name == i.contractName)
                contract = i;
        }
        // from address get bytecode
        string bin = getByteCode(address);
        return loadContract(bin, contract.abiJson);

    }

    //load contract with bin and json
    TargetExecutive LoadContractEth::loadContract(string bin, string json) {
        TargetContainer container;
        ContractABI ca(json);
        auto bin = fromHex(bin);
        TargetExecutive executive = container.loadContract(ca, bin);
        return executive;
    }

    //use JSON RPC POST request to get bytecode
    string LoadContractEth::getByteCode(string address) {
        const string url("https://mainnet.infura.io");
        string temp = "{ \"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"" + address + "\", \"pending\"],\"id\":1}";
        const char* data = temp.c_str();

        curl_global_init(CURL_GLOBAL_ALL);

        CURL* curl = curl_easy_init();
        struct curl_slist *headers = NULL;
        string response;

        headers = curl_slist_append(headers, "Content-Type: application/json");
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);
            curl_easy_setopt(curl, CURLOPT_POST, 1);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            auto res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                return "";
            }
            curl_easy_cleanup(curl);
            
        }
        curl_global_cleanup();
        json jsonObj;
        stringstream(response.c_str()) >> jsonObj;
        return jsonObj["result"];
    }

    //the callback function to handle the response
    size_t LoadContractEth::write_to_string(void *ptr, size_t size, size_t count, void *stream) {
        ((string*)stream)->append((char*)ptr, 0, size*count);
        return size*count;
    }

}