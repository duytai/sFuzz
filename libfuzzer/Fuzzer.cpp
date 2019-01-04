#include <thread>
#include <unistd.h>
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

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(FuzzParam fuzzParam): fuzzParam(fuzzParam){
  fill_n(fuzzStat.stageFinds, 32, 0);
}

/* Detect new exception */
u8 Fuzzer::hasNewExceptions(unordered_map<string, unordered_set<u64>> uexps) {
  int orginExceptions = 0;
  int newExceptions = 0;
  for (auto it : uniqExceptions) orginExceptions += it.second.size();
  for (auto it : uexps) {
    if (!uniqExceptions.count(it.first)) {
      uniqExceptions[it.first] = it.second;
    } else {
      for (auto v : it.second) {
        uniqExceptions[it.first].insert(v);
      }
    }
  }
  for (auto it : uniqExceptions) newExceptions += it.second.size();
  return newExceptions - orginExceptions;
}

/* Detect new bits by comparing tracebits to virginbits */
u8 Fuzzer::hasNewBits(unordered_set<uint64_t> _tracebits) {
  auto originSize = tracebits.size();
  for (auto it : _tracebits) tracebits.insert(it);
  auto newSize = tracebits.size();
  return newSize - originSize;
}

/* Detect new branch */
u8 Fuzzer::hasNewBranches(unordered_set<uint64_t> _branches) {
  auto originSize = branches.size();
  for (auto it : _branches) branches.insert(it);
  auto newSize = branches.size();
  return newSize - originSize;
}

ContractInfo Fuzzer::mainContract() {
  auto contractInfo = fuzzParam.contractInfo;
  auto first = contractInfo.begin();
  auto last = contractInfo.end();
  auto predicate = [](const ContractInfo& c) { return c.isMain; };
  auto it = find_if(first, last, predicate);
  return *it;
}

void Fuzzer::showStats(Mutation mutation, OracleResult oracleResult) {
  int numLines = 25, i = 0, expCout = 0;;
  if (!fuzzStat.clearScreen) {
    for (i = 0; i < numLines; i++) cout << endl;
    fuzzStat.clearScreen = true;
  }
  
  double duration = timer.elapsed();
  double fromLastNewPath = timer.elapsed() - fuzzStat.lastNewPath;
  for (i = 0; i < numLines; i++) cout << "\x1b[A";
  auto nowTrying = padStr(mutation.stageName, 20);
  auto stageExecProgress = to_string(mutation.stageCur) + "/" + to_string(mutation.stageMax);
  auto stageExecPercentage = to_string((int)((float) (mutation.stageCur) / mutation.stageMax * 100));
  auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", 20);
  auto allExecs = padStr(to_string(fuzzStat.totalExecs), 20);
  auto execSpeed = padStr(to_string((int)(fuzzStat.totalExecs / duration)), 20);
  auto cyclePercentage = (int)((float)(fuzzStat.idx + 1) / queues.size() * 100);
  auto cycleProgress = padStr(to_string(fuzzStat.idx + 1) + " (" + to_string(cyclePercentage) + "%)", 20);
  auto cycleDone = padStr(to_string(fuzzStat.queueCycle), 15);
  auto coveredTupleStr = padStr(to_string(fuzzStat.coveredTuples), 15);
  auto tupleSpeed = fuzzStat.coveredTuples ? mutation.dataSize * 8 / fuzzStat.coveredTuples : mutation.dataSize * 8;
  auto bitPerTupe = padStr(to_string(tupleSpeed) + " bits", 15);
  auto numBranches = padStr(to_string(branches.size()), 15);
  auto coverage = padStr(to_string((int) ((float) branches.size() / (fuzzStat.numJumpis * 2) * 100)) + " %", 15);
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
  auto random1 = to_string(fuzzStat.stageFinds[STAGE_RANDOM]) + "/" + to_string(mutation.stageCycles[STAGE_RANDOM]);
  auto random = padStr(random1, 30);
  auto pending = padStr(to_string(queues.size() - fuzzStat.idx - 1), 5);
  auto fav = count_if(queues.begin() + fuzzStat.idx + 1, queues.end(), [](FuzzItem item) {
    return !item.wasFuzzed;
  });
  auto pendingFav = padStr(to_string(fav), 5);
  auto maxdepthStr = padStr(to_string(fuzzStat.maxdepth), 5);
  for (auto exp: uniqExceptions) expCout+= exp.second.size();
  auto exceptionCount = padStr(to_string(expCout), 5);
  auto typeExceptionCount = padStr(to_string(uniqExceptions.size()), 5);
  auto contract = mainContract();
  printf(cGRN Bold "%sAFL Solidity v0.0.1 (%s)" cRST "\n", padStr("", 10).c_str(), contract.contractName.substr(0, 20).c_str());
  printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV2 bV2 bV5 bV bTR "\n");
  printf(bH "      run time : %s " bH "\n", formatDuration(duration).data());
  printf(bH " last new path : %s " bH "\n",formatDuration(fromLastNewPath).data());
  printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bV2 bV bTTR bV2 cGRN " overall results " cRST bV2 bV5 bV2 bV2 bV bRTR "\n");
  printf(bH "  now trying : %s" bH " cycles done : %s" bH "\n", nowTrying.c_str(), cycleDone.c_str());
  printf(bH " stage execs : %s" bH "      tuples : %s" bH "\n", stageExec.c_str(), coveredTupleStr.c_str());
  printf(bH " total execs : %s" bH "    branches : %s" bH "\n", allExecs.c_str(), numBranches.c_str());
  printf(bH "  exec speed : %s" bH "  bit/tuples : %s" bH "\n", execSpeed.c_str(), bitPerTupe.c_str());
  printf(bH "  cycle prog : %s" bH "    coverage : %s" bH "\n", cycleProgress.c_str(), coverage.c_str());
  printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bV2 bV bBTR bV10 bV bTTR bV cGRN " path geometry " cRST bV2 bV2 bRTR "\n");
  printf(bH "   bit flips : %s" bH "     pending : %s" bH "\n", bitflip.c_str(), pending.c_str());
  printf(bH "  byte flips : %s" bH " pending fav : %s" bH "\n", byteflip.c_str(), pendingFav.c_str());
  printf(bH " arithmetics : %s" bH "   max depth : %s" bH "\n", arithmetic.c_str(), maxdepthStr.c_str());
  printf(bH "  known ints : %s" bH " except type : %s" bH "\n", knownInts.c_str(), typeExceptionCount.c_str());
  printf(bH "  dictionary : %s" bH " uniq except : %s" bH "\n", dictionary.c_str(), exceptionCount.c_str());
  printf(bH "       havoc : %s" bH "                    " bH "\n", havoc.c_str());
  printf(bH "      random : %s" bH "                    " bH "\n", random.c_str());
  printf(bLTR bV5 cGRN " oracle yields " cRST bV bV10 bV5 bV bTTR bV2 bV10 bV bBTR bV bV2 bV5 bV5 bV2 bV2 bV5 bV bRTR "\n");
  auto toResult = [](u256 val){
    if (val > 0) return "found";
    return "none ";
  };
  printf(bH "            gasless send : %s " bH " dangerous delegatecall : %s " bH "\n", toResult(oracleResult.gaslessSend), toResult(oracleResult.dangerDelegateCall));
  printf(bH "      exception disorder : %s " bH "         freezing ether : %s " bH "\n", toResult(oracleResult.exceptionDisorder), toResult(oracleResult.freezingEther));
  printf(bH "              reentrancy : %s " bH "       integer overflow : %s " bH "\n", toResult(oracleResult.reentrancy), toResult(oracleResult.integerOverflow));
  printf(bH "    timestamp dependency : %s " bH "      integer underflow : %s " bH "\n", toResult(oracleResult.timestampDependency), toResult(oracleResult.integerUnderflow));
  printf(bH " block number dependency : %s " bH "%s" bH "\n", toResult(oracleResult.integerUnderflow), padStr(" ", 32).c_str());
  printf(bBL bV20 bV2 bV10 bV5 bV2 bV bBTR bV10 bV5 bV20 bV2 bV2 bBR "\n");
}

void Fuzzer::writeStats(Mutation mutation, OracleResult oracleResult) {
  auto contract = mainContract();
  ofstream stats(contract.contractName + "/stats.csv", ofstream::app);
  if (timer.elapsed() < fuzzParam.csvInterval) {
    stats << "duration, execution, speed, cycle, tuple, exception type, exception, flip1-tuple, flip1-exec, flip2-tuples, flip2-exec, flip4-tuple, flip4-exec, flip8-tuple, flip8-exec, flip16-tuple, flip16-exec, flip32-tuple, flip32-exec, arith8-tuple, arith8-exec, arith16-tuple, arith16-exec, arith32-tuple, arith32-exec, int8-tuple, int8-exec, int16-tuple, int16-exec, int32-tuple, int32-exec, ext_UO-tuple, ext_UO-exec, ext_AO-tuple, ext_AO-exec, havoc-tuple, havoc-exec, max depth, gasless, disorder, reentrancy, timestamp, number, delegate, freezing, branches, coverage" << endl;
  }
  cout << "** Write stats: " << timer.elapsed() << "" << endl;
  stats << timer.elapsed() << ",";
  stats << fuzzStat.totalExecs << ",";
  stats << fuzzStat.totalExecs / (double) timer.elapsed() << ",";
  stats << fuzzStat.queueCycle << ",";
  stats << fuzzStat.coveredTuples << ",";
  int expCout = 0;
  for (auto exp: uniqExceptions) expCout += exp.second.size();
  stats << uniqExceptions.size() << ",";
  stats << expCout << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP1] << ",";
  stats << mutation.stageCycles[STAGE_FLIP1] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP2] << ",";
  stats << mutation.stageCycles[STAGE_FLIP2] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP4] << ",";
  stats << mutation.stageCycles[STAGE_FLIP4] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP8] << ",";
  stats << mutation.stageCycles[STAGE_FLIP8] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP16] << ",";
  stats << mutation.stageCycles[STAGE_FLIP16] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP32] << ",";
  stats << mutation.stageCycles[STAGE_FLIP32] << ",";
  stats << fuzzStat.stageFinds[STAGE_ARITH8] << ",";
  stats << mutation.stageCycles[STAGE_ARITH8] << ",";
  stats << fuzzStat.stageFinds[STAGE_ARITH16] << ",";
  stats << mutation.stageCycles[STAGE_ARITH16] << ",";
  stats << fuzzStat.stageFinds[STAGE_ARITH32] << ",";
  stats << mutation.stageCycles[STAGE_ARITH32] << ",";
  stats << fuzzStat.stageFinds[STAGE_INTEREST8] << ",";
  stats << mutation.stageCycles[STAGE_INTEREST8] << ",";
  stats << fuzzStat.stageFinds[STAGE_INTEREST16] << ",";
  stats << mutation.stageCycles[STAGE_INTEREST16] << ",";
  stats << fuzzStat.stageFinds[STAGE_INTEREST32] << ",";
  stats << mutation.stageCycles[STAGE_INTEREST32] << ",";
  stats << fuzzStat.stageFinds[STAGE_EXTRAS_AO] << ",";
  stats << mutation.stageCycles[STAGE_EXTRAS_AO] << ",";
  stats << fuzzStat.stageFinds[STAGE_EXTRAS_UO] << ",";
  stats << mutation.stageCycles[STAGE_EXTRAS_UO] << ",";
  stats << fuzzStat.stageFinds[STAGE_HAVOC] << ",";
  stats << mutation.stageCycles[STAGE_HAVOC] << ",";
  stats << fuzzStat.maxdepth << ",";
  stats << oracleResult.gaslessSend << ",";
  stats << oracleResult.exceptionDisorder << ",";
  stats << oracleResult.reentrancy << ",";
  stats << oracleResult.timestampDependency << ",";
  stats << oracleResult.blockNumDependency << ",";
  stats << oracleResult.dangerDelegateCall << ",";
  stats << oracleResult.freezingEther << ",";
  stats << branches.size() << ",";
  stats << (int) ((float) branches.size() / (fuzzStat.numJumpis * 2) * 100) << ",";
  stats << endl;
  stats.close();
}

void Fuzzer::writeVulnerability(bytes data, string prefix) {
  auto contract = mainContract();
  ContractABI ca(contract.abiJson);
  ca.updateTestData(data);
  string ret = ca.toStandardJson();
  ofstream test(contract.contractName + "/" + prefix + ".json");
  test << ret;
  test.close();
}

void Fuzzer::writeTestcase(bytes data, string prefix) {
  auto contract = mainContract();
  ContractABI ca(contract.abiJson);
  ca.updateTestData(data);
  fuzzStat.numTest ++;
  string ret = ca.toStandardJson();
  // write decoded data
  ofstream test(contract.contractName + "/" + prefix + to_string(fuzzStat.numTest) + "__.json");
  test << ret;
  test.close();
  // write full data
  ofstream fullTest(contract.contractName + "/" + prefix + toString(fuzzStat.numTest) + "__.bin");
  fullTest << toHex(data) << endl;
  fullTest.close();
}

void Fuzzer::writeException(bytes data, string prefix) {
  auto contract = mainContract();
  ContractABI ca(contract.abiJson);
  ca.updateTestData(data);
  fuzzStat.numException ++;
  string ret = ca.toStandardJson();
  ofstream exp(contract.contractName + "/" + prefix + to_string(fuzzStat.numException) + "__.json");
  exp << ret;
  exp.close();
}
/* Save data if interest */
FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, int depth) {
  auto revisedData = ContractABI::postprocessTestData(data);
  FuzzItem item(revisedData);
  item.res = te.exec(revisedData, fuzzParam.logger);
  item.wasFuzzed = false;
  fuzzStat.totalExecs ++;
  if (hasNewBits(item.res.tracebits)) {
    if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
    item.depth = depth + 1;
    queues.push_back(item);
    fuzzStat.lastNewPath = timer.elapsed();
    fuzzStat.coveredTuples = tracebits.size();
    writeTestcase(revisedData, "__TEST__");
    fuzzParam.logger->writeOut(true);
  } else fuzzParam.logger->clear();
  if (hasNewExceptions(item.res.uniqExceptions)) {
    writeException(revisedData, "__EXCEPTION__");
  }
  hasNewBranches(item.res.branches);
  return item;
}

/* Start fuzzing */
void Fuzzer::start() {
  TargetContainer container;
  Dictionary codeDict, addressDict;
  unordered_map<u64, u64> showMap;
  for (auto contractInfo : fuzzParam.contractInfo) {
    ContractABI ca(contractInfo.abiJson);
    auto bin = fromHex(contractInfo.bin);
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
      fuzzParam.logger = new Logger(contractName, fuzzParam.log);
      staticAnalyze(bin, [&](Instruction inst) {
        if (inst == Instruction::JUMPI) fuzzStat.numJumpis ++;
      });
      saveIfInterest(executive, ca.randomTestcase(), 0);
      int origHitCount = queues.size();
      while (true) {
        FuzzItem curItem = queues[fuzzStat.idx];
        Mutation mutation(curItem, make_tuple(codeDict, addressDict));
        auto save = [&](bytes data) {
          auto item = saveIfInterest(executive, data, curItem.depth);
          /* Show every one second */
          u64 dur = timer.elapsed();
          if (!showMap.count(dur)) {
            showMap.insert(make_pair(dur, 1));
            if (fuzzParam.reporter == CSV_FILE) {
              if (dur % fuzzParam.csvInterval == 0)
                writeStats(mutation, container.oracleResult());
            } else if (fuzzParam.reporter == TERMINAL) {
              showStats(mutation, container.oracleResult());
            }
          }
          /* Analyze every 1000 test cases */
          if (!(fuzzStat.totalExecs % 500)) {
            auto data = container.analyze();
            for (auto it : data) {
              writeVulnerability(get<1>(it), get<0>(it));
            }
          }
          /* Stop program */
          if (timer.elapsed() > fuzzParam.duration) {
            auto data = container.analyze();
            for (auto it : data) {
              writeVulnerability(get<1>(it), get<0>(it));
            }
            writeStats(mutation, container.oracleResult());
            exit(0);
          }
          return item;
        };
        switch (fuzzParam.mode) {
          case AFL: {
            if (!curItem.wasFuzzed) {
              mutation.singleWalkingBit(save);
              fuzzStat.stageFinds[STAGE_FLIP1] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.twoWalkingBit(save);
              fuzzStat.stageFinds[STAGE_FLIP2] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.fourWalkingBit(save);
              fuzzStat.stageFinds[STAGE_FLIP4] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.singleWalkingByte(save);
              fuzzStat.stageFinds[STAGE_FLIP8] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.twoWalkingByte(save);
              fuzzStat.stageFinds[STAGE_FLIP16] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.fourWalkingByte(save);
              fuzzStat.stageFinds[STAGE_FLIP32] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.singleArith(save);
              fuzzStat.stageFinds[STAGE_ARITH8] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.twoArith(save);
              fuzzStat.stageFinds[STAGE_ARITH16] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.fourArith(save);
              fuzzStat.stageFinds[STAGE_ARITH32] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.singleInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST8] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.twoInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST16] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.fourInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST32] += queues.size() - origHitCount;
              origHitCount = queues.size();

              mutation.overwriteWithDictionary(save);
              fuzzStat.stageFinds[STAGE_EXTRAS_UO] += queues.size() - origHitCount;
              origHitCount = queues.size();
              
              mutation.overwriteWithAddressDictionary(save);
              fuzzStat.stageFinds[STAGE_EXTRAS_AO] += queues.size() - origHitCount;
              origHitCount = queues.size();
                
              mutation.havoc(tracebits, save, true);
              fuzzStat.stageFinds[STAGE_HAVOC] += queues.size() - origHitCount;
              origHitCount = queues.size();
              
              queues[fuzzStat.idx].wasFuzzed = true;
            } else {
              mutation.havoc(tracebits, save, true);
              fuzzStat.stageFinds[STAGE_HAVOC] += queues.size() - origHitCount;
              origHitCount = queues.size();
              
              if (mutation.splice(queues)) {
                mutation.havoc(tracebits, save, true);
                fuzzStat.stageFinds[STAGE_HAVOC] += queues.size() - origHitCount;
                origHitCount = queues.size();
              };
            }
            break;
          }
          case RANDOM: {
            mutation.random(save);
            fuzzStat.stageFinds[STAGE_RANDOM] += queues.size() - origHitCount;
            origHitCount = queues.size();
            break;
          }
          case HAVOC_COMPLEX: {
            mutation.havoc(tracebits, save, true);
            fuzzStat.stageFinds[STAGE_HAVOC] += queues.size() - origHitCount;
            origHitCount = queues.size();
            break;
          }
          case HAVOC_SIMPLE: {
            mutation.havoc(tracebits, save, false);
            fuzzStat.stageFinds[STAGE_HAVOC] += queues.size() - origHitCount;
            origHitCount = queues.size();
            break;
          }
        }
        fuzzStat.idx = (fuzzStat.idx + 1) % queues.size();
        if (fuzzStat.idx == 0) fuzzStat.queueCycle ++;
      }
    }
  }
}
