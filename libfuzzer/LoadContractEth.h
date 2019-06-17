#pragma once
#include "Common.h"
#include "ContractABI.h"
#include "FuzzItem.h"
#include "Mutation.h"
#include "Util.h"
#include "Fuzzer.h"
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/client.h>
#include <liboracle/Common.h>
#include <sstream>
#include <string>
#include <vector>

using namespace std;
using namespace dev;

namespace fuzzer
{
class LoadContractEth
{
public:
    TargetExecutive loadContractfromEthereum(
        std::string name, std::string address, vector<ContractInfo> contractInfo);
    TargetExecutive loadContract(std::string bin, std::string json);
    string getByteCode(string address);
};
}  // namespace fuzzer
