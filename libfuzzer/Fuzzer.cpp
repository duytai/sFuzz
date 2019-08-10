#include <fstream>
#include "Fuzzer.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "Logger.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
namespace pt = boost::property_tree;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(FuzzParam fuzzParam): fuzzParam(fuzzParam){
  fill_n(fuzzStat.stageFinds, 32, 0);
}

/* Detect new exception */
void Fuzzer::updateExceptions(unordered_set<string> exps) {
  for (auto it: exps) uniqExceptions.insert(it);
}

/* Detect new bits by comparing tracebits to virginbits */
void Fuzzer::updateTracebits(unordered_set<string> _tracebits) {
  for (auto it: _tracebits) tracebits.insert(it);
}

void Fuzzer::updatePredicates(unordered_map<string, u256> _pred) {
  for (auto it : _pred) {
    predicates.insert(it.first);
  };
  // Remove covered predicates
  for(auto it = predicates.begin(); it != predicates.end(); ) {
    if (tracebits.count(*it)) {
      it = predicates.erase(it);
    } else {
      ++it;
    }
  }
}

ContractInfo Fuzzer::mainContract() {
  auto contractInfo = fuzzParam.contractInfo;
  auto first = contractInfo.begin();
  auto last = contractInfo.end();
  auto predicate = [](const ContractInfo& c) { return c.isMain; };
  auto it = find_if(first, last, predicate);
  return *it;
}

void Fuzzer::showStats(const Mutation &mutation, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis) {
  int numLines = 24, i = 0;
  if (!fuzzStat.clearScreen) {
    for (i = 0; i < numLines; i++) cout << endl;
    fuzzStat.clearScreen = true;
  }
  double duration = timer.elapsed();
  double fromLastNewPath = timer.elapsed() - fuzzStat.lastNewPath;
  for (i = 0; i < numLines; i++) cout << "\x1b[A";
  auto nowTrying = padStr(mutation.stageName, 20);
  auto stageExecProgress = to_string(mutation.stageCur) + "/" + to_string(mutation.stageMax);
  auto stageExecPercentage = mutation.stageMax == 0 ? to_string(100) : to_string((uint64_t)((float) (mutation.stageCur) / mutation.stageMax * 100));
  auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", 20);
  auto allExecs = padStr(to_string(fuzzStat.totalExecs), 20);
  auto execSpeed = padStr(to_string((int)(fuzzStat.totalExecs / duration)), 20);
  auto cyclePercentage = (int)((float)(fuzzStat.idx + 1) / leaders.size() * 100);
  auto cycleProgress = padStr(to_string(fuzzStat.idx + 1) + " (" + to_string(cyclePercentage) + "%)", 20);
  auto cycleDone = padStr(to_string(fuzzStat.queueCycle), 15);
  auto numBranches = padStr(to_string(tracebits.size()), 15);
  auto totalBranches = (get<0>(validJumpis).size() + get<1>(validJumpis).size()) * 2;
  auto coverage = padStr(to_string((uint64_t)((float)(tracebits.size()) / totalBranches) * 100) + "%", 15);
  auto flip1 = to_string(fuzzStat.stageFinds[STAGE_FLIP1]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP1]);
  auto flip2 = to_string(fuzzStat.stageFinds[STAGE_FLIP2]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP2]);
  auto flip4 = to_string(fuzzStat.stageFinds[STAGE_FLIP4]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP4]);
  auto bitflip = padStr(flip1 + ", " + flip2 + ", " + flip4, 30);
  auto byte1 = to_string(fuzzStat.stageFinds[STAGE_FLIP8]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP8]);
  auto byte2 = to_string(fuzzStat.stageFinds[STAGE_FLIP16]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP16]);
  auto byte4 = to_string(fuzzStat.stageFinds[STAGE_FLIP32]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP32]);
  auto byteflip = padStr(byte1 + ", " + byte2 + ", " + byte4, 30);
  auto arith1 = to_string(fuzzStat.stageFinds[STAGE_ARITH8]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH8]);
  auto arith2 = to_string(fuzzStat.stageFinds[STAGE_ARITH16]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH16]);
  auto arith4 = to_string(fuzzStat.stageFinds[STAGE_ARITH32]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH32]);
  auto arithmetic = padStr(arith1 + ", " + arith2 + ", " + arith4, 30);
  auto int1 = to_string(fuzzStat.stageFinds[STAGE_INTEREST8]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST8]);
  auto int2 = to_string(fuzzStat.stageFinds[STAGE_INTEREST16]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST16]);
  auto int4 = to_string(fuzzStat.stageFinds[STAGE_INTEREST32]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST32]);
  auto knownInts = padStr(int1 + ", " + int2 + ", " + int4, 30);
  auto addrDict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_AO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_AO]);
  auto dict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_UO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_UO]);
  auto dictionary = padStr(dict1 + ", " + addrDict1, 30);
  auto hav1 = to_string(fuzzStat.stageFinds[STAGE_HAVOC]) + "/" + to_string(mutation.stageCycles[STAGE_HAVOC]);
  auto havoc = padStr(hav1, 30);
  auto pending = padStr(to_string(leaders.size() - fuzzStat.idx - 1), 5);
  auto fav = count_if(leaders.begin(), leaders.end(), [](const pair<string, Leader> &p) {
    return !p.second.item.fuzzedCount;
  });
  auto pendingFav = padStr(to_string(fav), 5);
  auto maxdepthStr = padStr(to_string(fuzzStat.maxdepth), 5);
  auto exceptionCount = padStr(to_string(uniqExceptions.size()), 5);
  auto predicateSize = padStr(to_string(predicates.size()), 5);
  auto contract = mainContract();
  auto toResult = [](bool val) { return val ? "found" : "none "; };
  printf(cGRN Bold "%sAFL Solidity v0.0.1 (%s)" cRST "\n", padStr("", 10).c_str(), contract.contractName.substr(0, 20).c_str());
  printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV2 bV2 bV5 bV bTR "\n");
  printf(bH "      run time : %s " bH "\n", formatDuration(duration).data());
  printf(bH " last new path : %s " bH "\n",formatDuration(fromLastNewPath).data());
  printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bV2 bV bTTR bV2 cGRN " overall results " cRST bV2 bV5 bV2 bV2 bV bRTR "\n");
  printf(bH "  now trying : %s" bH " cycles done : %s" bH "\n", nowTrying.c_str(), cycleDone.c_str());
  printf(bH " stage execs : %s" bH "    branches : %s" bH "\n", stageExec.c_str(), numBranches.c_str());
  printf(bH " total execs : %s" bH "    coverage : %s" bH "\n", allExecs.c_str(), coverage.c_str());
  printf(bH "  exec speed : %s" bH "               %s" bH "\n", execSpeed.c_str(), padStr("", 15).c_str());
  printf(bH "  cycle prog : %s" bH "               %s" bH "\n", cycleProgress.c_str(), padStr("", 15).c_str());
  printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bV2 bV bBTR bV10 bV bTTR bV cGRN " path geometry " cRST bV2 bV2 bRTR "\n");
  printf(bH "   bit flips : %s" bH "     pending : %s" bH "\n", bitflip.c_str(), pending.c_str());
  printf(bH "  byte flips : %s" bH " pending fav : %s" bH "\n", byteflip.c_str(), pendingFav.c_str());
  printf(bH " arithmetics : %s" bH "   max depth : %s" bH "\n", arithmetic.c_str(), maxdepthStr.c_str());
  printf(bH "  known ints : %s" bH " uniq except : %s" bH "\n", knownInts.c_str(), exceptionCount.c_str());
  printf(bH "  dictionary : %s" bH "  predicates : %s" bH "\n", dictionary.c_str(), predicateSize.c_str());
  printf(bH "       havoc : %s" bH "               %s" bH "\n", havoc.c_str(), padStr("", 5).c_str());
  printf(bLTR bV5 cGRN " oracle yields " cRST bV bV10 bV5 bV bTTR bV2 bV10 bV bBTR bV bV2 bV5 bV5 bV2 bV2 bV5 bV bRTR "\n");
  printf(bH "            gasless send : %s " bH " dangerous delegatecall : %s " bH "\n", toResult(vulnerabilities[GASLESS_SEND]), toResult(vulnerabilities[DELEGATE_CALL]));
  printf(bH "      exception disorder : %s " bH "         freezing ether : %s " bH "\n", toResult(vulnerabilities[EXCEPTION_DISORDER]), toResult(vulnerabilities[FREEZING]));
  printf(bH "              reentrancy : %s " bH "       integer overflow : %s " bH "\n", toResult(vulnerabilities[REENTRANCY]), toResult(vulnerabilities[OVERFLOW]));
  printf(bH "    timestamp dependency : %s " bH "      integer underflow : %s " bH "\n", toResult(vulnerabilities[TIME_DEPENDENCY]), toResult(vulnerabilities[UNDERFLOW]));
  printf(bH " block number dependency : %s " bH "%s" bH "\n", toResult(vulnerabilities[NUMBER_DEPENDENCY]), padStr(" ", 32).c_str());
  printf(bBL bV20 bV2 bV10 bV5 bV2 bV bBTR bV10 bV5 bV20 bV2 bV2 bBR "\n");
}

void Fuzzer::writeStats(const Mutation &mutation) {
  auto contract = mainContract();
  stringstream ss;
  pt::ptree root;
  ofstream stats(contract.contractName + "/stats.json");
  root.put("duration", timer.elapsed());
  root.put("totalExecs", fuzzStat.totalExecs);
  root.put("speed", (double) fuzzStat.totalExecs / timer.elapsed());
  root.put("queueCycles", fuzzStat.queueCycle);
  root.put("uniqExceptions", uniqExceptions.size());
  pt::write_json(ss, root);
  stats << ss.str() << endl;
  stats.close();
}

/* Save data if interest */
FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis) {
  auto revisedData = ContractABI::postprocessTestData(data);
  FuzzItem item(revisedData);
  item.res = te.exec(revisedData, validJumpis);
  Logger::debug(Logger::testFormat(item.data));
  fuzzStat.totalExecs ++;
  for (auto tracebit: item.res.tracebits) {
    if (!tracebits.count(tracebit)) {
      // Remove leader
      auto fi = [=](const pair<string, Leader>& p) { return p.first == tracebit;};
      auto it = find_if(leaders.begin(), leaders.end(), fi);
      if (it!= leaders.end()) leaders.erase(it);
      // Insert leader
      item.depth = depth + 1;
      auto leader = Leader(item, 0);
      leaders.insert(make_pair(tracebit, leader));
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      fuzzStat.lastNewPath = timer.elapsed();
      Logger::debug("Cover new branch "  + tracebit);
      Logger::debug(Logger::testFormat(item.data));
    }
  }
  for (auto predicateIt: item.res.predicates) {
    auto fi = [=](const pair<string, Leader>& p) { return p.first == predicateIt.first;};
    auto leaderIt = find_if(leaders.begin(), leaders.end(), fi);
    if (
        leaderIt != leaders.end() // Found Leader
        && leaderIt->second.comparisonValue > 0 // Not a covered branch
        && leaderIt->second.comparisonValue > predicateIt.second // ComparisonValue is better
    ) {
      // Debug now
      Logger::debug("Found better test case for uncovered branch " + predicateIt.first);
      Logger::debug("prev: " + leaderIt->second.comparisonValue.str());
      Logger::debug("now : " + predicateIt.second.str());
      // Stop debug
      leaders.erase(leaderIt); // Remove leader
      item.depth = depth + 1;
      auto leader = Leader(item, predicateIt.second);
      leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      fuzzStat.lastNewPath = timer.elapsed();
      Logger::debug(Logger::testFormat(item.data));
    } else if (leaderIt == leaders.end()) {
      auto leader = Leader(item, predicateIt.second);
      item.depth = depth + 1;
      leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      fuzzStat.lastNewPath = timer.elapsed();
      // Debug
      Logger::debug("Found new uncovered branch");
      Logger::debug("now: " + predicateIt.second.str());
      Logger::debug(Logger::testFormat(item.data));
    }
  }
  updateExceptions(item.res.uniqExceptions);
  updateTracebits(item.res.tracebits);
  updatePredicates(item.res.predicates);
  return item;
}

/* Stop fuzzing */
void Fuzzer::stop() {
  Logger::debug("==== TEST CASES ====");
  for (auto it : leaders) {
    Logger::debug("BR " + it.first);
    Logger::debug(Logger::testFormat(it.second.item.data));
  }
  exit(1);
}

/* Start fuzzing */
void Fuzzer::start() {
  TargetContainer container;
  Dictionary codeDict, addressDict;
  unordered_set<u64> showSet;
  for (auto contractInfo : fuzzParam.contractInfo) {
    auto isAttacker = contractInfo.contractName.find(fuzzParam.attackerName) != string::npos;
    if (!contractInfo.isMain && !isAttacker) continue;
    ContractABI ca(contractInfo.abiJson);
    auto bin = fromHex(contractInfo.bin);
    auto binRuntime = fromHex(contractInfo.binRuntime);
    // Accept only valid jumpis
    auto executive = container.loadContract(bin, ca);
    if (!contractInfo.isMain) {
      /* Load Attacker agent contract */
      auto data = ca.randomTestcase();
      auto revisedData = ContractABI::postprocessTestData(data);
      executive.deploy(revisedData, EMPTY_ONOP);
      addressDict.fromAddress(executive.addr.asBytes());
    } else {
      auto contractName = contractInfo.contractName;
      boost::filesystem::remove_all(contractName);
      boost::filesystem::create_directory(contractName);
      codeDict.fromCode(bin);
      auto validJumpis = findValidJumpis(bin, binRuntime);
      saveIfInterest(executive, ca.randomTestcase(), 0, validJumpis);
      int originHitCount = leaders.size();
      // No branch
      if (!originHitCount) {
        cout << "No branch" << endl;
        stop();
      }
      // There are uncovered branches or not
      auto fi = [&](const pair<string, Leader> &p) { return p.second.comparisonValue != 0;};
      auto numUncoveredBranches = count_if(leaders.begin(), leaders.end(), fi);
      if (!numUncoveredBranches) {
        auto curItem = (*leaders.begin()).second.item;
        Mutation mutation(curItem, make_tuple(codeDict, addressDict));
        vulnerabilities = container.analyze();
        switch (fuzzParam.reporter) {
          case TERMINAL: {
            showStats(mutation, validJumpis);
            break;
          }
          case JSON: {
            writeStats(mutation);
            break;
          }
          case BOTH: {
            showStats(mutation, validJumpis);
            writeStats(mutation);
            break;
          }
        }
        stop();
      }
      // Jump to fuzz loop
      while (true) {
        Logger::debug("== LEADERS ==");
        for (auto leaderIt : leaders) {
          if (leaderIt.second.comparisonValue != 0) {
            Logger::debug("Branch \t\t\t : " + leaderIt.first);
            Logger::debug("Score \t\t\t : " + leaderIt.second.comparisonValue.str());
            Logger::debug("Fuzzed \t\t\t : " + to_string(leaderIt.second.item.fuzzedCount));
            Logger::debug("Depth \t\t\t : " + to_string(leaderIt.second.item.depth));
            Logger::debug(Logger::testFormat(leaderIt.second.item.data));
          }
        }
        Logger::debug("== END LEADERS ==");
        for (auto &leaderIt : leaders) {
          auto curItem = leaderIt.second.item;
          auto comparisonValue = leaderIt.second.comparisonValue;
          Mutation mutation(curItem, make_tuple(codeDict, addressDict));
          auto save = [&](bytes data) {
            auto item = saveIfInterest(executive, data, curItem.depth, validJumpis);
            /* Show every one second */
            u64 duration = timer.elapsed();
            if (!showSet.count(duration)) {
              showSet.insert(duration);
              if (duration % fuzzParam.analyzingInterval == 0) {
                vulnerabilities = container.analyze();
              }
              switch (fuzzParam.reporter) {
                case TERMINAL: {
                  showStats(mutation, validJumpis);
                  break;
                }
                case JSON: {
                  writeStats(mutation);
                  break;
                }
                case BOTH: {
                  showStats(mutation, validJumpis);
                  writeStats(mutation);
                  break;
                }
              }
            }
            /* Stop program */
            u64 speed = (u64)(fuzzStat.totalExecs / timer.elapsed());
            if (timer.elapsed() > fuzzParam.duration || speed <= 10 || !predicates.size()) {
              vulnerabilities = container.analyze();
              switch(fuzzParam.reporter) {
                case TERMINAL: {
                  showStats(mutation, validJumpis);
                  break;
                }
                case JSON: {
                  writeStats(mutation);
                  break;
                }
                case BOTH: {
                  showStats(mutation, validJumpis);
                  writeStats(mutation);
                  break;
                }
              }
              stop();
            }
            return item;
          };
          // If it is uncovered branch
          if (comparisonValue != 0) {
            // Haven't fuzzed before
            if (!curItem.fuzzedCount) {
              Logger::debug("SingleWalkingBit");
              mutation.singleWalkingBit(save);
              fuzzStat.stageFinds[STAGE_FLIP1] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("TwoWalkingBit");
              mutation.twoWalkingBit(save);
              fuzzStat.stageFinds[STAGE_FLIP2] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("FourWalkingBtit");
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

              Logger::debug("SingleArith");
              mutation.singleArith(save);
              fuzzStat.stageFinds[STAGE_ARITH8] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("TwoArith");
              mutation.twoArith(save);
              fuzzStat.stageFinds[STAGE_ARITH16] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("FourArith");
              mutation.fourArith(save);
              fuzzStat.stageFinds[STAGE_ARITH32] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("SingleInterest");
              mutation.singleInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST8] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("TwoInterest");
              mutation.twoInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST16] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("FourInterest");
              mutation.fourInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST32] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("overwriteDict");
              mutation.overwriteWithDictionary(save);
              fuzzStat.stageFinds[STAGE_EXTRAS_UO] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("overwriteAddress");
              mutation.overwriteWithAddressDictionary(save);
              fuzzStat.stageFinds[STAGE_EXTRAS_AO] += leaders.size() - originHitCount;
              originHitCount = leaders.size();

              Logger::debug("havoc");
              mutation.havoc(save);
              fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
              originHitCount = leaders.size();
            } else {
              Logger::debug("havoc");
              mutation.havoc(save);
              fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
              originHitCount = leaders.size();
              Logger::debug("Splice");
              vector<FuzzItem> queues = {};
              for (auto it : leaders) queues.push_back(it.second.item);
              if (mutation.splice(queues)) {
                Logger::debug("havoc");
                mutation.havoc(save);
                fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
                originHitCount = leaders.size();
              }
            }
          }
          leaderIt.second.item.fuzzedCount += 1;
          fuzzStat.idx = (fuzzStat.idx + 1) % leaders.size();
          if (fuzzStat.idx == 0) fuzzStat.queueCycle ++;
        }
      }
    }
  }
}
