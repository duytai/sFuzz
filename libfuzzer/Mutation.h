#pragma once
#include "ContractABI.h"
#include "Dictionary.h"
#include "FuzzItem.h"
#include "TargetContainer.h"
#include <vector>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer
{
using Dicts = tuple<Dictionary /* code */, Dictionary /* address */>;
class Mutation
{
    Dicts dicts;
    uint64_t effCount = 0;
    bytes eff;
    void flipbit(int pos);

public:
    FuzzItem curFuzzItem;
    uint64_t dataSize = 0;
    uint64_t stageMax = 0;
    uint64_t stageCur = 0;
    string stageName = "";
    static uint64_t stageCycles[32];
    Mutation(FuzzItem item, Dicts dicts);
    void singleWalkingBit(OnMutateFunc cb);
    void twoWalkingBit(OnMutateFunc cb);
    void fourWalkingBit(OnMutateFunc cb);
    void singleWalkingByte(OnMutateFunc cb);
    void twoWalkingByte(OnMutateFunc cb);
    void fourWalkingByte(OnMutateFunc cb);
    void singleArith(OnMutateFunc cb);
    void twoArith(OnMutateFunc cb);
    void fourArith(OnMutateFunc cb);
    void singleInterest(OnMutateFunc cb);
    void twoInterest(OnMutateFunc cb);
    void fourInterest(OnMutateFunc cb);
    void overwriteWithAddressDictionary(OnMutateFunc cb);
    void overwriteWithDictionary(OnMutateFunc cb);
    void random(OnMutateFunc cb);
    void havoc(OnMutateFunc cb);
    void addFunc(OnMutateFunc cb, ContractABI ca);
    void removeFunc(OnMutateFunc cb, ContractABI ca);
    void swapFunc(OnMutateFunc cb, ContractABI ca);

    // return total mutate count
    int active(OnMutateFunc cb, vector<Pattern*> uncoveredPatterns,
        vector<Pattern*> dynamicPatterns,
        unordered_map<string, unordered_map<uint32_t, bytes>> readVarFuncs,
        unordered_map<string, unordered_map<uint32_t, bytes>> writeVarFuncs, 
        ContractABI ca);
    bool splice(vector<FuzzItem> items);
};
}  // namespace fuzzer
