#pragma once
#define BATCH_SIZE 10
#include "ContractABI.h"
#include "FuzzItem.h"
#include "Mutation.h"
#include "Util.h"
#include "Logger.h"
#include <liboracle/Common.h>
#include <iostream>
#include <vector>

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer
{
enum FuzzMode
{
    AFL
};
enum Reporter
{
    TERMINAL,
    JSON,
    BOTH
};
struct ContractInfo
{
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
    string srcmap;
    string srcmapRuntime;
    string source;
    vector<string> constantFunctionSrcmap;
    bool isMain;
};
struct FuzzParam
{
    vector<ContractInfo> contractInfo;
    FuzzMode mode;
    Reporter reporter;
    int duration;
    int analyzingInterval;
    string attackerName;
};
struct FuzzStat
{
    int idx = 0;   // branch
    int pIdx = 0;  // pattern
    int oIdx = 0;
    int orderMutateCount = 0;
    int patternNum = 0;
    int len2=0;
    int len3=0;
    int len4=0;
    uint64_t maxdepth = 0;
    bool clearScreen = false;
    int totalExecs = 0;
    double totalExecDur = 0;
    int queueCycle = 0;
    int pQueueCycle = 0;
    int stageFinds[32];
    double lastNewPath = 0;
};
struct Leader
{
    FuzzItem item;
    u256 comparisonValue = 0;
    Leader(FuzzItem _item, u256 _comparisionValue) : item(_item) {
        comparisonValue = _comparisionValue;
    }
};
class Fuzzer
{
    bool passive;
    int funcNum;
    vector<bool> vulnerabilities;
    vector<string> queues;                              // covered & just-missed branches
    unordered_set<string> tracebits;                    // 已经cover的branch集合
    vector<Pattern*> patterns;                          // 已经cover的pattern
    vector<Pattern*> uncoveredPatterns;                 // 等待cover的小地址Patterns
    vector<Pattern*> dynamicPatterns;                   // 等待cover的非定长元素Patterns
    int funcNums;                                       // 合约中非view函数个数
    ofstream expFile;                                   // 实验文件
    int smallAddressPatternNum;                         // 之前的小地址Pattern个数
    int prevBranchNum;                                  // 之前覆盖的分支数量
    unordered_set<string> failed_properties;            // 找到了违背
    unordered_map<string, unordered_map<uint32_t, bytes>> readVarFuncs;
    unordered_map<string, unordered_map<uint32_t, bytes>> writeVarFuncs;
    unordered_set<string> predicates;
    unordered_map<string, Leader> leaders;
    vector<Leader> newPatternLeaders;
    unordered_map<uint64_t, string> snippets;
    unordered_set<string> uniqExceptions;
    Timer timer;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
    void writeStats(const Mutation& mutation);
    ContractInfo mainContract();

public:
    Fuzzer(FuzzParam fuzzParam);
    FuzzItem saveIfInterest(TargetExecutive& te,
        pair<bytes /*data*/, vector<size_t> /*order*/> data, uint64_t depth,
        const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis,
        unordered_map<uint32_t, size_t> funcIdxs, bool newOrder );
    void showStats(const Mutation& mutation,
        const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis);
    void updateTracebits(unordered_set<string> tracebits);
    void updatePredicates(unordered_map<string, u256> predicates);
    void updateExceptions(unordered_set<string> uniqExceptions);
    void start();
    void stop(const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis, ContractABI ca);
};
}  // namespace fuzzer
