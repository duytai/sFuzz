#include "Fuzzer.h"
#include "BytecodeBranch.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "Mutation.h"
#include <fstream>

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
namespace pt = boost::property_tree;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(FuzzParam fuzzParam) : fuzzParam(fuzzParam)
{
    fill_n(fuzzStat.stageFinds, 32, 0);
}

/* Detect new exception */
void Fuzzer::updateExceptions(unordered_set<string> exps)
{
    for (auto it : exps)
        uniqExceptions.insert(it);
}

/* Detect new bits by comparing tracebits to virginbits */
void Fuzzer::updateTracebits(unordered_set<string> _tracebits)
{
    for (auto it : _tracebits)
        tracebits.insert(it);
}

void Fuzzer::updatePredicates(unordered_map<string, u256> _pred)
{
    for (auto it : _pred)
    {
        predicates.insert(it.first);
    };
    // Remove covered predicates
    for (auto it = predicates.begin(); it != predicates.end();)
    {
        if (tracebits.count(*it))
        {
            it = predicates.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

ContractInfo Fuzzer::mainContract()
{
    auto contractInfo = fuzzParam.contractInfo;
    auto first = contractInfo.begin();
    auto last = contractInfo.end();
    auto predicate = [](const ContractInfo &c) { return c.isMain; };
    auto it = find_if(first, last, predicate);
    return *it;
}

void Fuzzer::showStats(const Mutation &mutation,
                       const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis)
{
    int numLines = 25, i = 0;
    if (!fuzzStat.clearScreen)
    {
        for (i = 0; i < numLines; i++)
            cout << endl;
        fuzzStat.clearScreen = true;
    }
    double duration = timer.elapsed();
    double fromLastNewPath = timer.elapsed() - fuzzStat.lastNewPath;
    for (i = 0; i < numLines; i++)
        cout << "\x1b[A";
    auto nowTrying = padStr(mutation.stageName, 20);
    auto stageExecProgress = to_string(mutation.stageCur) + "/" + to_string(mutation.stageMax);
    auto stageExecPercentage =
        mutation.stageMax == 0 ? to_string(100) : to_string((uint64_t)((float)(mutation.stageCur) / mutation.stageMax * 100));
    auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", 20);
    auto allExecs = padStr(to_string(fuzzStat.totalExecs), 20);
    auto execSpeed = padStr(to_string((int)(fuzzStat.totalExecs / duration)), 20);
    auto cyclePercentage = (uint64_t)((float)(fuzzStat.idx + 1) / leaders.size() * 100);
    auto cycleProgress =
        padStr(to_string(fuzzStat.idx + 1) + " (" + to_string(cyclePercentage) + "%)", 20);
    auto cycleDone = padStr(to_string(fuzzStat.queueCycle), 15);
    auto totalBranches = (get<0>(validJumpis).size() + get<1>(validJumpis).size()) * 2;
    auto numBranches = padStr(to_string(totalBranches), 15);
    auto coverage = padStr(
        to_string((uint64_t)((float)tracebits.size() / (float)totalBranches * 100)) + "%", 15);
    auto flip1 = to_string(fuzzStat.stageFinds[STAGE_FLIP1]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP1]);
    auto flip2 = to_string(fuzzStat.stageFinds[STAGE_FLIP2]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP2]);
    auto flip4 = to_string(fuzzStat.stageFinds[STAGE_FLIP4]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP4]);
    auto bitflip = padStr(flip1 + ", " + flip2 + ", " + flip4, 30);
    auto byte1 = to_string(fuzzStat.stageFinds[STAGE_FLIP8]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP8]);
    auto byte2 = to_string(fuzzStat.stageFinds[STAGE_FLIP16]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP16]);
    auto byte4 = to_string(fuzzStat.stageFinds[STAGE_FLIP32]) + "/" +
                 to_string(mutation.stageCycles[STAGE_FLIP32]);
    auto byteflip = padStr(byte1 + ", " + byte2 + ", " + byte4, 30);
    auto arith1 = to_string(fuzzStat.stageFinds[STAGE_ARITH8]) + "/" +
                  to_string(mutation.stageCycles[STAGE_ARITH8]);
    auto arith2 = to_string(fuzzStat.stageFinds[STAGE_ARITH16]) + "/" +
                  to_string(mutation.stageCycles[STAGE_ARITH16]);
    auto arith4 = to_string(fuzzStat.stageFinds[STAGE_ARITH32]) + "/" +
                  to_string(mutation.stageCycles[STAGE_ARITH32]);
    auto arithmetic = padStr(arith1 + ", " + arith2 + ", " + arith4, 30);
    auto int1 = to_string(fuzzStat.stageFinds[STAGE_INTEREST8]) + "/" +
                to_string(mutation.stageCycles[STAGE_INTEREST8]);
    auto int2 = to_string(fuzzStat.stageFinds[STAGE_INTEREST16]) + "/" +
                to_string(mutation.stageCycles[STAGE_INTEREST16]);
    auto int4 = to_string(fuzzStat.stageFinds[STAGE_INTEREST32]) + "/" +
                to_string(mutation.stageCycles[STAGE_INTEREST32]);
    auto knownInts = padStr(int1 + ", " + int2 + ", " + int4, 30);
    auto addrDict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_AO]) + "/" +
                     to_string(mutation.stageCycles[STAGE_EXTRAS_AO]);
    auto dict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_UO]) + "/" +
                 to_string(mutation.stageCycles[STAGE_EXTRAS_UO]);
    auto dictionary = padStr(dict1 + ", " + addrDict1, 30);
    auto hav1 = to_string(fuzzStat.stageFinds[STAGE_HAVOC]) + "/" +
                to_string(mutation.stageCycles[STAGE_HAVOC]);
    auto pCycleDone = padStr(to_string(fuzzStat.pQueueCycle), 15);
    auto havoc = padStr(hav1, 30);
    auto pending = padStr(to_string(leaders.size() - fuzzStat.idx - 1), 5);
    auto fav = count_if(leaders.begin(), leaders.end(),
                        [](const pair<string, Leader> &p) { return !p.second.item.fuzzedCount; });
    auto pendingFav = padStr(to_string(fav), 5);
    auto maxdepthStr = padStr(to_string(fuzzStat.maxdepth), 5);
    auto exceptionCount = padStr(to_string(uniqExceptions.size()), 5);
    auto predicateSize = padStr(to_string(predicates.size()), 5);
    auto contract = mainContract();
    if (prevBranchNum != tracebits.size())
    {
        prevBranchNum = tracebits.size();
        expFile << "time: " + to_string(duration) + ", branches:" + to_string(prevBranchNum) << endl;
    } 
    if (smallAddressPatternNum != fuzzStat.patternNum)
    {
        smallAddressPatternNum = fuzzStat.patternNum;
        expFile << "time: " + to_string(duration) + ", patterns:" + to_string(smallAddressPatternNum) << endl;
    }
    auto toResult = [](bool val) { return val ? "found" : "none "; };
    printf(cGRN Bold "%sMapV2+AFL Solidity v0.0.1 (%s)" cRST "\n", padStr("", 10).c_str(),
           contract.contractName.substr(0, 20).c_str());
    printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV2 bV2 bV5 bV bTR "\n");
    printf(bH "      run time : %s " bH "\n", formatDuration(duration).data());
    printf(bH " last new path : %s " bH "\n", formatDuration(fromLastNewPath).data());
    printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bV2 bV bTTR bV2 cGRN
                         " overall results " cRST bV2 bV5 bV2 bV2 bV bRTR "\n");
    printf(bH "  now trying : %s" bH " cycles done : %s" bH "\n", nowTrying.c_str(),
           cycleDone.c_str());
    printf(bH " stage execs : %s" bH "    branches : %s" bH "\n", stageExec.c_str(),
           numBranches.c_str());
    printf(
        bH " total execs : %s" bH "    coverage : %s" bH "\n", allExecs.c_str(), coverage.c_str());
    printf(bH "  exec speed : %s" bH " orderMutate : %s" bH "\n", execSpeed.c_str(),
           padStr(to_string(fuzzStat.orderMutateCount), 15).c_str());
    printf(bH "  cycle prog : %s" bH "pCycles done : %s" bH "\n", cycleProgress.c_str(),
           padStr(to_string(fuzzStat.pQueueCycle), 15).c_str());
    printf(bH " pattern Num : %s" bH "curPatternIdx: %s" bH "\n",
           padStr(to_string(patterns.size()), 20).c_str(),
           padStr(to_string(fuzzStat.pIdx), 15).c_str());
    printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bV2 bV bBTR bV10 bV bTTR bV cGRN
                         " path geometry " cRST bV2 bV2 bRTR "\n");
    printf(bH "   bit flips : %s" bH "     pending : %s" bH "\n", bitflip.c_str(), pending.c_str());
    printf(bH "  byte flips : %s" bH " pending fav : %s" bH "\n", byteflip.c_str(),
           pendingFav.c_str());
    printf(bH " arithmetics : %s" bH "   max depth : %s" bH "\n", arithmetic.c_str(),
           maxdepthStr.c_str());
    printf(bH "  known ints : %s" bH " uniq except : %s" bH "\n", knownInts.c_str(),
           exceptionCount.c_str());
    printf(bH "  dictionary : %s" bH "  predicates : %s" bH "\n", dictionary.c_str(),
           predicateSize.c_str());
    printf(bH "       havoc : %s" bH "               %s" bH "\n", havoc.c_str(),
           padStr("", 5).c_str());
    printf(bLTR bV5 cGRN " oracle yields " cRST bV bV10 bV5 bV bTTR bV2 bV10 bV bBTR bV bV2 bV5 bV5
               bV2 bV2 bV5 bV bRTR "\n");
    printf(bH "            gasless send : %s " bH " dangerous delegatecall : %s " bH "\n", toResult(vulnerabilities[GASLESS_SEND]), toResult(vulnerabilities[DELEGATE_CALL]));
    printf(bH "      exception disorder : %s " bH "         freezing ether : %s " bH "\n", toResult(vulnerabilities[EXCEPTION_DISORDER]), toResult(vulnerabilities[FREEZING]));
    printf(bH "              reentrancy : %s " bH "       integer overflow : %s " bH "\n", toResult(vulnerabilities[REENTRANCY]), toResult(vulnerabilities[ORACLE_OVERFLOW]));
    printf(bH "    timestamp dependency : %s " bH "      integer underflow : %s " bH "\n", toResult(vulnerabilities[TIME_DEPENDENCY]), toResult(vulnerabilities[ORACLE_UNDERFLOW]));
    printf(bH " block number dependency : %s " bH "%s" bH "\n", toResult(vulnerabilities[NUMBER_DEPENDENCY]), padStr(" ", 32).c_str());
    printf(bBL bV20 bV2 bV10 bV5 bV2 bV bBTR bV10 bV5 bV20 bV2 bV2 bBR "\n");
}

void Fuzzer::writeStats(const Mutation &mutation)
{
    auto contract = mainContract();
    stringstream ss;
    pt::ptree root;
    ofstream stats(contract.contractName + "/stats.json");
    root.put("duration", timer.elapsed());
    root.put("totalExecs", fuzzStat.totalExecs);
    root.put("speed", (double)fuzzStat.totalExecs / timer.elapsed());
    root.put("queueCycles", fuzzStat.queueCycle);
    root.put("uniqExceptions", uniqExceptions.size());
    pt::write_json(ss, root);
    stats << ss.str() << endl;
    stats.close();
}

/* Save data if interest */
FuzzItem Fuzzer::saveIfInterest(TargetExecutive &te,
                                pair<bytes /*data*/, vector<size_t> /*order*/> data, uint64_t depth,
                                const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis,
                                unordered_map<uint32_t, size_t> funcIdxs, bool newOrder)
{
    auto revisedData = ContractABI::postprocessTestData(data.first);
    FuzzItem item(revisedData, data.second); 
    if (passive)
    {
        item.res = te.execP(make_pair(revisedData, data.second), validJumpis, newOrder, tracebits);
    }
    else
    {
        item.res = te.execA(make_pair(revisedData, data.second), validJumpis, newOrder, tracebits);
    }

    if (newOrder)
    {
        fuzzStat.orderMutateCount++;
    }
    fuzzStat.totalExecDur += item.res.execDur;
    fuzzStat.totalExecs += data.second.size();
    for (auto tracebit : item.res.newTracebits)
    { 
        auto lIt = find_if(leaders.begin(), leaders.end(),
                           [=](const pair<string, Leader> &p) { return p.first == tracebit; });
        if (lIt != leaders.end())
            leaders.erase(lIt);
        auto qIt = find_if(queues.begin(), queues.end(), [=](const string &s) { return s == tracebit; });
        if (qIt == queues.end())
            queues.push_back(tracebit);
        // Insert leader
        item.depth = depth + 1;
        auto leader = Leader(item, 0);  
        leaders.insert(make_pair(tracebit, leader));
        if (depth + 1 > fuzzStat.maxdepth)
            fuzzStat.maxdepth = depth + 1;
        fuzzStat.lastNewPath = timer.elapsed();
        Logger::debug("Cover new branch " + tracebit);
        Logger::debug(Logger::testFormat(item.data));
    }
    for (auto predicateIt : item.res.predicates)
    {  
        auto lIt = find_if(leaders.begin(), leaders.end(),
                           [=](const pair<string, Leader> &p) { return p.first == predicateIt.first; });
        if (lIt != leaders.end()                                //  Leader Founded
            && lIt->second.comparisonValue > 0                  // Not a covered branch
            && lIt->second.comparisonValue > predicateIt.second // ComparisonValue is better
        )
        {
            // Debug now 
            Logger::debug("Found better test case for uncovered branch " + predicateIt.first);
            Logger::debug("prev: " + lIt->second.comparisonValue.str());
            Logger::debug("now : " + predicateIt.second.str());
            // Stop debug
            leaders.erase(lIt); // Remove leader
            item.depth = depth + 1;
            auto leader = Leader(item, predicateIt.second);
            leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
            if (depth + 1 > fuzzStat.maxdepth)
                fuzzStat.maxdepth = depth + 1;
            fuzzStat.lastNewPath = timer.elapsed();
            Logger::debug(Logger::testFormat(item.data));
        }
        else if (lIt == leaders.end())
        {
            auto leader = Leader(item, predicateIt.second);
            item.depth = depth + 1;
            leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
            queues.push_back(predicateIt.first);
            if (depth + 1 > fuzzStat.maxdepth)
                fuzzStat.maxdepth = depth + 1;
            fuzzStat.lastNewPath = timer.elapsed();
            // Debug
            Logger::debug("Found new uncovered branch");
            Logger::debug("now: " + predicateIt.second.str());
            Logger::debug(Logger::testFormat(item.data));
        }
    }
    bool newPatternFound = false;
    bool newStaticSizedPatternFound = false;
    for (auto pattern : item.res.patterns)
    {
        auto pIt = find_if(patterns.begin(), patterns.end(),
                           [=](const Pattern *p) { return isTheSamePattern(p, pattern); });
        if (pIt == patterns.end())
        {
            newPatternFound = true;
            patterns.push_back(pattern);
            bool stat = true;
            for (auto node : pattern->nodes)
            {
                if (node.var.size() > 8)
                {
                    stat = false;
                    break;
                }
            }
            if (stat)
            {
                fuzzStat.patternNum++;
                newStaticSizedPatternFound = true;
                if (pattern->nodes.size() == 2)
                {
                    fuzzStat.len2++;
                }

                if (pattern->nodes.size() == 3)
                {
                    fuzzStat.len3++;
                }
                if (pattern->nodes.size() == 4)
                {
                    fuzzStat.len4++;
                }
                auto uIt = find_if(uncoveredPatterns.begin(), uncoveredPatterns.end(),
                                   [=](const Pattern *p) { return isTheSamePattern(p, pattern); });
                if (uIt != uncoveredPatterns.end())
                {
                    uncoveredPatterns.erase(uIt);
                }
            }
            if (depth + 1 > fuzzStat.maxdepth)
                fuzzStat.maxdepth = depth + 1;
            fuzzStat.lastNewPath = timer.elapsed();
        }
    }
    if (newPatternFound)
    {
        if (newStaticSizedPatternFound || !UR(50))
        {
            auto leader = Leader(item, 0 /*Unused*/);
            newPatternLeaders.push_back(leader);
        }
    }

    if (!passive)
    {
        unordered_map<size_t, vector<string>> newReadFuncVars; 
        unordered_map<size_t, vector<string>> newWriteFuncVars;
        auto funcsExec = item.res.funcsExec;

        for (int i = 1; i < funcsExec.size(); i++)
        {
            auto func = get<1>(funcsExec[i]);
            auto funcData = get<2>(funcsExec[i]);
            auto vars = get<3>(funcsExec[i]);
            for (auto var : vars)
            {
                auto rIt = find_if(readVarFuncs[var].begin(), readVarFuncs[var].end(),
                                   [&](const pair<uint32_t, bytes> &p) { return p.first == func; });
                if (rIt == readVarFuncs[var].end() && isRead(get<4>(funcsExec[i]), var))
                {
                    readVarFuncs[var][func] = funcData;
                    newReadFuncVars[i].push_back(var);
                }
                auto wIt = find_if(writeVarFuncs[var].begin(), writeVarFuncs[var].end(),
                                   [&](const pair<uint32_t, bytes> &p) { return p.first == func; });
                if (wIt == writeVarFuncs[var].end() && isWrite(get<4>(funcsExec[i]), var))
                {
                    writeVarFuncs[var][func] = funcData;
                    newWriteFuncVars[i].push_back(var);
                }
            }
        }
        for (auto it = newReadFuncVars.begin(); it != newReadFuncVars.end(); ++it)
        {
            auto idx = it->first;
            auto func = get<1>(funcsExec[idx]);
            for (auto var : it->second)
            {
                auto pPatterns = getPossiblePatterns(var, READ, func, readVarFuncs[var], writeVarFuncs[var]);
                for (auto possiblePattern : pPatterns)
                {
                    auto pIt = find_if(patterns.begin(), patterns.end(),
                                       [&](const Pattern *p) { return isTheSamePattern(p, possiblePattern); });
                    if (pIt == patterns.end())
                    {
                        bool stat = true;
                        for (auto node : possiblePattern->nodes)
                        {
                            if (node.var.size() > 8)
                            {
                                stat = false;
                                break;
                            }
                        }
                        if (stat)
                        {
                            uncoveredPatterns.push_back(possiblePattern);
                        }
                        else
                        {
                            dynamicPatterns.push_back(possiblePattern);
                        }
                    }
                }
            }
        }
        for (auto it = newWriteFuncVars.begin(); it != newWriteFuncVars.end(); ++it)
        {
            auto idx = it->first;
            auto func = get<1>(funcsExec[idx]);
            for (auto var : it->second)
            {

                auto pPatterns = getPossiblePatterns(var, READ, func, readVarFuncs[var], writeVarFuncs[var]);
                for (auto possiblePattern : pPatterns)
                {
                    auto pIt = find_if(patterns.begin(), patterns.end(),
                                       [&](const Pattern *p) { return isTheSamePattern(p, possiblePattern); });
                    if (pIt == patterns.end())
                    {
                        bool stat = true;
                        for (auto node : possiblePattern->nodes)
                        {
                            if (node.var.size() > 8)
                            {
                                stat = false;
                                break;
                            }
                        }
                        if (stat)
                        {
                            uncoveredPatterns.push_back(possiblePattern);
                        }
                        else
                        {
                            dynamicPatterns.push_back(possiblePattern);
                        }
                    }
                }
            }
        }
    }
    updateExceptions(item.res.uniqExceptions);
    updateTracebits(item.res.newTracebits);
    updatePredicates(item.res.predicates);

    return item;
}

/* Stop fuzzing */
void Fuzzer::stop(const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis, ContractABI ca)
{
    Logger::debug("== TEST ==");
    unordered_map<uint64_t, uint64_t> brs;
    for (auto it : leaders)
    {
        
        auto pc = stoi(splitString(it.first, ':')[0]);
        // Covered
        if (it.second.comparisonValue == 0)
        {
            if (brs.find(pc) == brs.end())
            {
                brs[pc] = 1;
            }
            else
            {
                brs[pc] += 1;
            }
        }
        Logger::debug("BR " + it.first);
        Logger::debug("ComparisonValue " + it.second.comparisonValue.str());
        Logger::debug(Logger::testFormat(it.second.item.data));
    }
    Logger::debug("== END TEST ==");
    for (auto it : snippets)
    {
        if (brs.find(it.first) == brs.end())
        {
            Logger::info(">> Unreachable");
            Logger::info(it.second);
        }
        else
        {
            if (brs[it.first] == 1)
            {
                Logger::info(">> Haft");
                Logger::info(it.second);
            }
            else
            {
                Logger::info(">> Full");
                Logger::info(it.second);
            }
        }
    }
    auto toResult = [](bool val) { return val ? "found" : "none"; };
    auto contract = mainContract();
    // expFile << "======stop fuzzing======" << endl;
    // expFile << "Duration: " + to_string(timer.elapsed()) + "s" << endl;
    // expFile << "Total exec duration: " + to_string(fuzzStat.totalExecDur) << endl;
    // expFile << "Total exec functions: " + to_string(fuzzStat.totalExecs) << endl;
    // expFile << "CoveredBranchesNum: " + to_string(tracebits.size()) << endl;
    // expFile << "FuncsNum: " + to_string(funcNums) << endl;
    // expFile << "OrderMutateCount: " + to_string(fuzzStat.orderMutateCount) << endl;
    // expFile << "Len-2 Patterns: " + to_string(fuzzStat.len2) << endl;
    // expFile << "Len-3 Patterns: " + to_string(fuzzStat.len3) << endl;
    // expFile << "Len-4 Patterns: " + to_string(fuzzStat.len4) << endl;
    // // expFile << "aribitrary write: " + string(toResult(vulnerabilities[ARBITRARY_WRITE])) << endl;
    // // expFile << "blockstate dependency: " + string(toResult(vulnerabilities[BLOCKSTATE_DEPENDENCY])) << endl;
    // // expFile << "control hijack: " + string(toResult(vulnerabilities[CONTROL_HIJACK])) << endl;
    // // expFile << "integer bug: " + string(toResult(vulnerabilities[INTEGER_BUG])) << endl;
    // // expFile << "mishandled exception: " + string(toResult(vulnerabilities[EXCEPTION_DISORDER])) << endl;
    // // expFile << "multiple send: " + string(toResult(vulnerabilities[MULTIPLE_SEND])) << endl;
    // // expFile << "reentrancy: " + string(toResult(vulnerabilities[REENTRANCY])) << endl;
    // expFile << "transactional origin use: " + string(toResult(vulnerabilities[TRANSACTIONAL_ORIGIN_USE])) << endl;

    exit(1);
}

/* Start fuzzing */
void Fuzzer::start()
{
    TargetContainer container;
    Dictionary codeDict, addressDict;
    unordered_set<u64> showSet;
    for (auto contractInfo : fuzzParam.contractInfo)
    {
        auto isAttacker = contractInfo.contractName.find(fuzzParam.attackerName) != string::npos;
        if (!contractInfo.isMain && !isAttacker)
            continue;
        ContractABI ca(contractInfo.abiJson);
        auto bin = fromHex(contractInfo.bin);
        auto binRuntime = fromHex(contractInfo.binRuntime);

        // Accept only valid jumpi
        auto executive = container.loadContract(bin, ca); 
        if (!contractInfo.isMain)
        {
            /* Load Attacker agent contract */
            auto data = ca.randomTestcase();
            auto revisedData = ContractABI::postprocessTestData(data);
            executive.deploy(revisedData, EMPTY_ONOP);
            addressDict.fromAddress(executive.addr.asBytes());
        }
        else
        {
            auto contractName = contractInfo.contractName;
            expFile = ofstream( contractName + "_CMB.txt", ios_base::app);
            smallAddressPatternNum = 0;
            prevBranchNum = 0;
            passive = true;
            boost::filesystem::remove_all(contractName);
            codeDict.fromCode(bin);
            auto bytecodeBranch = BytecodeBranch(contractInfo);
            auto validJumpis = bytecodeBranch.findValidJumpis();
            snippets = bytecodeBranch.snippets;
            auto totalBranches = (get<0>(validJumpis).size() + get<1>(validJumpis).size()) * 2;
            expFile << "TotalBranchesNum: " + to_string(totalBranches) << endl;
            vector<size_t> order;
            for (size_t i = 0; i < ca.fds.size(); ++i)
            {
                if (ca.fds[i].name != "")
                {
                    order.push_back(i);
                }
            }
            funcNums = ca.fds.size();
            auto testCase = ca.randomTestcase();
            saveIfInterest(executive, make_pair(testCase, order), 0, validJumpis, ca.funcIdxs, true);
            if (!(get<0>(validJumpis).size() + get<1>(validJumpis).size()))
            {
                cout << "No valid jumpi" << endl;
                stop(validJumpis, ca);
            }
            int originHitCount = leaders.size(); // Hit的Branch
            // No branch
            if (!originHitCount)
            {
                cout << "No branch" << endl;
                stop(validJumpis, ca);
            }
            // There are uncovered branches or not
            auto fi = [&](const pair<string, Leader> &p) { return p.second.comparisonValue != 0; };
            auto numUncoveredBranches =
                count_if(leaders.begin(), leaders.end(), fi); 
            if (!numUncoveredBranches)
            { 
                auto curItem = (*leaders.begin()).second.item;
                Mutation mutation(curItem, make_tuple(codeDict, addressDict));
                vulnerabilities = container.analyze();
                switch (fuzzParam.reporter)
                {
                case TERMINAL:
                {
                    showStats(mutation, validJumpis);
                    break;
                }
                case JSON:
                {
                    writeStats(mutation);
                    break;
                }
                case BOTH:
                {
                    showStats(mutation, validJumpis);
                    writeStats(mutation);
                    break;
                }
                }
                stop(validJumpis,ca);
            }
            // Jump to fuzz loop
            while (true)
            {
                auto leaderIt = leaders.find(queues[fuzzStat.idx]);
                auto curItem = leaderIt->second.item; 

                auto comparisonValue = leaderIt->second.comparisonValue;
                if (comparisonValue != 0)
                {
                    Logger::debug(" == Leader ==");
                    Logger::debug("Branch \t\t\t\t " + leaderIt->first);
                    Logger::debug("Comp \t\t\t\t " + comparisonValue.str());
                    Logger::debug("Fuzzed \t\t\t\t " + to_string(curItem.fuzzedCount));
                    Logger::debug(Logger::testFormat(curItem.data));
                }
                Mutation mutation(curItem, make_tuple(codeDict, addressDict));
                bool newOrder = false;
                auto save = [&](bytes data, vector<size_t> order) {
                    auto item = saveIfInterest(executive, make_pair(data, order), curItem.depth,
                                               validJumpis, ca.funcIdxs, newOrder);
                    /* Show every one second */
                    u64 duration = timer.elapsed();
                    if (!showSet.count(duration))
                    {
                        showSet.insert(duration);
                        if (duration % fuzzParam.analyzingInterval == 0)
                        {
                            vulnerabilities = container.analyze();
                        }
                        switch (fuzzParam.reporter)
                        {
                        case TERMINAL:
                        {
                            showStats(mutation, validJumpis);
                            break;
                        }
                        case JSON:
                        {
                            writeStats(mutation);
                            break;
                        }
                        case BOTH:
                        {
                            showStats(mutation, validJumpis);
                            writeStats(mutation);
                            break;
                        }
                        }
                    }
                    /* Passively Mutate First then Actively*/
                    if (passive && timer.elapsed() > fuzzParam.duration*4/5)
                    {
                        expFile << "passive-active: " + to_string(timer.elapsed()) << endl;
                        passive = false; 
                        unordered_map<string, Leader> tmpL;
                        for (auto it : leaders)
                        {
                            auto traceBit = it.first;
                            auto revisedData = ContractABI::postprocessTestData(it.second.item.data);
                            pair<bytes, vector<size_t>> p = make_pair(it.second.item.data, it.second.item.order); 
                            FuzzItem item = saveIfInterest(executive, p, 0, validJumpis, ca.funcIdxs, false);  
                            Leader l(item, it.second.comparisonValue);
                            tmpL.insert(make_pair(it.first, l));
                        } 
                        vector<Leader> tmp;
                        for (int i =0; i < newPatternLeaders.size(); i++)
                        {
                            auto leader = newPatternLeaders[i];
                            auto revisedData = ContractABI::postprocessTestData(leader.item.data);
                            pair<bytes, vector<size_t>> p = make_pair(leader.item.data, leader.item.order);
                            FuzzItem item = saveIfInterest(executive, p, 0, validJumpis, ca.funcIdxs, false);  
                            Leader l(item, 0);
                            tmp.push_back(l);
                        } 
                        leaders.clear();
                        newPatternLeaders.clear();
                        for (auto it: tmpL)
                        {
                            leaders.emplace(it.first, it.second);
                        }
                        
                        for (int i = 0; i < tmp.size(); i++)
                        {
                            newPatternLeaders.push_back(tmp[i]);
                        } 
                    }

                    /* Stop program */
                    u64 speed = (u64)(fuzzStat.totalExecs / timer.elapsed());
                    if (timer.elapsed() > fuzzParam.duration || !predicates.size())
                    {
                        vulnerabilities = container.analyze();
                        switch (fuzzParam.reporter)
                        {
                        case TERMINAL:
                        {
                            showStats(mutation, validJumpis);
                            break;
                        }
                        case JSON:
                        {
                            writeStats(mutation);
                            break;
                        }
                        case BOTH:
                        {
                            showStats(mutation, validJumpis);
                            writeStats(mutation);
                            break;
                        }
                        }
                        stop(validJumpis, ca);
                    }
                    return item;
                };
                // If it is uncovered branch or it covers new Pattern.
                if (comparisonValue != 0)
                { 
                    // Haven't fuzzed before
                    if (!curItem.fuzzedCount)
                    {
                        newOrder = true;

                        if (passive)
                        {
                            expFile << "passive" << endl;
                            Logger::debug("SwapFunc");
                            mutation.swapFunc(save, ca);
                            fuzzStat.stageFinds[STAGE_SWAP] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();

                            Logger::debug("RemoveFunc");
                            mutation.removeFunc(save, ca);
                            fuzzStat.stageFinds[STAGE_REMOVE] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();

                            Logger::debug("AddFunc");
                            mutation.addFunc(save, ca);
                            fuzzStat.stageFinds[STAGE_ADD] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();
                        }
                        else
                        {
                            expFile << "active" << endl;
                            Logger::debug("ActiveMutation");
                            int c = mutation.active(save, uncoveredPatterns, dynamicPatterns, writeVarFuncs,
                                                    readVarFuncs, ca);
                            fuzzStat.stageFinds[STAGE_PASSIVE] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();
                        }

                        newOrder = false;
                        Logger::debug("SingleWalkingBit");
                        mutation.singleWalkingBit(save);
                        fuzzStat.stageFinds[STAGE_FLIP1] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("TwoWalkingBit");
                        mutation.twoWalkingBit(save);
                        fuzzStat.stageFinds[STAGE_FLIP2] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("FourWalkingBit");
                        mutation.fourWalkingBit(save);
                        fuzzStat.stageFinds[STAGE_FLIP4] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("SingleWalkingByte");
                        mutation.singleWalkingByte(save);
                        fuzzStat.stageFinds[STAGE_FLIP8] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("TwoWalkingByte");
                        mutation.twoWalkingByte(save);
                        fuzzStat.stageFinds[STAGE_FLIP16] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("FourWalkingByte");
                        mutation.fourWalkingByte(save);
                        fuzzStat.stageFinds[STAGE_FLIP32] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("overwriteAddress");
                        mutation.overwriteWithAddressDictionary(save);
                        fuzzStat.stageFinds[STAGE_EXTRAS_AO] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("havoc");
                        mutation.havoc(save);
                        fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();
                    }
                    else
                    {
                        newOrder = true;

                        if (passive)
                        {
                            expFile << "passive" << endl;
                            Logger::debug("SwapFunc");
                            mutation.swapFunc(save, ca);
                            fuzzStat.stageFinds[STAGE_SWAP] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();

                            Logger::debug("RemoveFunc");
                            mutation.removeFunc(save, ca);
                            fuzzStat.stageFinds[STAGE_REMOVE] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();

                            Logger::debug("AddFunc");
                            mutation.addFunc(save, ca);
                            fuzzStat.stageFinds[STAGE_ADD] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();
                        }
                        else
                        {
                            expFile << "active" << endl;
                            Logger::debug("ActiveMutation");
                            int c = mutation.active(save, uncoveredPatterns, dynamicPatterns, writeVarFuncs,
                                                    readVarFuncs, ca);
                            fuzzStat.stageFinds[STAGE_PASSIVE] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();
                        }

                        newOrder = false;
                        Logger::debug("havoc");
                        mutation.havoc(save);
                        fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("Splice");
                        vector<FuzzItem> items = {};
                        for (auto it : leaders)
                            items.push_back(it.second.item);
                        if (mutation.splice(items))
                        {
                            Logger::debug("havoc");
                            mutation.havoc(save);
                            fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
                            originHitCount = leaders.size();
                        }
                    }
                }
                leaderIt->second.item.fuzzedCount += 1;
                fuzzStat.idx = (fuzzStat.idx + 1) % leaders.size();
                if (fuzzStat.idx == 0)
                    fuzzStat.queueCycle++;

                if (newPatternLeaders.size() > 0)
                {
                    auto curItem = newPatternLeaders[fuzzStat.pIdx].item;

                    Mutation mutation(curItem, make_tuple(codeDict, addressDict));

                    newOrder = true; 
                    if (passive)
                    {
                        expFile << "passive" << endl;
                        Logger::debug("SwapFunc");
                        mutation.swapFunc(save, ca);
                        fuzzStat.stageFinds[STAGE_SWAP] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("RemoveFunc");
                        mutation.removeFunc(save, ca);
                        fuzzStat.stageFinds[STAGE_REMOVE] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();

                        Logger::debug("AddFunc");
                        mutation.addFunc(save, ca);
                        fuzzStat.stageFinds[STAGE_ADD] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();
                    }
                    else
                    {
                        expFile << "active" << endl;
                        Logger::debug("ActiveMutation");
                        int c = mutation.active(save, uncoveredPatterns, dynamicPatterns, writeVarFuncs,
                                                readVarFuncs, ca);
                        fuzzStat.stageFinds[STAGE_PASSIVE] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();
                    }

                    newOrder = false;
                    Logger::debug("havoc");
                    mutation.havoc(save);
                    fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
                    originHitCount = leaders.size();

                    Logger::debug("Splice");
                    vector<FuzzItem> items = {};
                    for (auto it : leaders)
                        items.push_back(it.second.item);
                    if (mutation.splice(items))
                    {
                        Logger::debug("havoc");
                        mutation.havoc(save);
                        fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
                        originHitCount = leaders.size();
                    }

                    fuzzStat.pIdx = (fuzzStat.pIdx + 1) % newPatternLeaders.size();
                    if (fuzzStat.pIdx == 0)
                        fuzzStat.pQueueCycle++;
                }
                
            }
        }
    }
}
