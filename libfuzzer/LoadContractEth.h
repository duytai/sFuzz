#pragma once
#include <iostream>
#include <vector>
#include <liboracle/Common.h>
#include "ContractABI.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Mutation.h"
#include "Common.h"

using namespace std;
using namespace dev;

namespace fuzzer {
    class LoadContractEth {
        private:
            size_t write_to_string(void *ptr, size_t size, size_t count, void *stream);
        public:
            TargetExecutive loadContractfromEthereum(string name, string address, vector<ContractInfo> contractInfo);
            TargetExecutive loadContract(string bin, string json);
            string getByteCode(string address);
    }
}