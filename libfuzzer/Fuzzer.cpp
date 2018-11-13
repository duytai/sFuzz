#include <thread>
#include <unistd.h>
#include "Fuzzer.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(bytes code, ContractABI ca, CFG cfg): ca(ca), code(code), virginbits(bytes(MAP_SIZE, 255)), container(code, ca), cfg(cfg) {
  idx = 0;
  totalExecs = 0;
  clearScreen = false;
  queueCycle = 0;
}

/* Detect new branch by comparing tracebits to virginbits */
u8 Fuzzer::hasNewBits(bytes tracebits) {
  u8 ret = 0;
  u32 i = (MAP_SIZE >> 2);
  u32* current = (u32*) tracebits.data();
  u32* virgin = (u32*) virginbits.data();
  while (i--) {
    if (unlikely(*current) && unlikely(*current & *virgin)) {
      if (likely(ret < 2)) {
        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;
        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;
      }
      *virgin &= ~*current;
    }
    current++;
    virgin++;
  }
  return ret;
}

void Fuzzer::showStats(Mutation mutation, FuzzItem item) {
  int numLines = 18, i = 0;
  if (!clearScreen) {
    for (i = 0; i < numLines; i++) cout << endl;
    printf(CURSOR_HIDE);
    clearScreen = true;
  }
  int totalBranches = cfg.totalCount();
  double duration = timer.elapsed();
  double fromLastNewPath = timer.elapsed() - lastNewPath;
  for (i = 0; i < numLines; i++) cout << "\x1b[A";
  auto nowTrying = padStr(mutation.stageName, 17);
  auto stageExecProgress = to_string(mutation.stageCur) + "/" + to_string(mutation.stageMax);
  auto stageExecPercentage = to_string((int)((float) (mutation.stageCur) / mutation.stageMax * 100));
  auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", 17);
  auto allExecs = padStr(to_string(totalExecs), 17);
  auto execSpeed = padStr(to_string((int)(totalExecs / duration)), 17);
  auto cyclePercentage = (int)((float)(idx + 1) / queues.size() * 100);
  auto cycleProgress = padStr(to_string(idx + 1) + " (" + to_string(cyclePercentage) + "%)", 17);
  auto cycleDone = padStr(to_string(queueCycle), 11);
  auto coveredBranches = (MAP_SIZE << 3) - coutBits(virginbits.data());
  auto coveredBranchesStr = padStr(to_string(coveredBranches) + " (" + to_string((int)((float)coveredBranches/ totalBranches * 100)) + "%)", 11);
  auto numBytes = countBytes(item.res.tracebits.data());
  auto bytePercentage = (int)(numBytes * 100 / MAP_SIZE);
  auto mapDensitive = padStr(to_string(numBytes) + " (" + to_string(bytePercentage) + "%)", 11);
  auto tupleSpeed = coveredBranches ? mutation.dataSize * 8 / coveredBranches : mutation.dataSize * 8;
  auto countCoverage = padStr(to_string(tupleSpeed) + " bits", 11);
  auto flip1 = to_string(stageFinds[STAGE_FLIP1]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP1]);
  auto flip2 = to_string(stageFinds[STAGE_FLIP2]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP2]);
  auto flip4 = to_string(stageFinds[STAGE_FLIP4]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP4]);
  auto bitflip = padStr(flip1 + ", " + flip2 + ", " + flip4, 30);
  auto byte1 = to_string(stageFinds[STAGE_FLIP8]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP8]);
  auto byte2 = to_string(stageFinds[STAGE_FLIP16]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP16]);
  auto byte4 = to_string(stageFinds[STAGE_FLIP32]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP32]);
  auto byteflip = padStr(byte1 + ", " + byte2 + ", " + byte4, 30);
  auto arith1 = to_string(stageFinds[STAGE_ARITH8]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH8]);
  auto arith2 = to_string(stageFinds[STAGE_ARITH16]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH16]);
  auto arith4 = to_string(stageFinds[STAGE_ARITH32]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH32]);
  auto arithmetic = padStr(arith1 + ", " + arith2 + ", " + arith4, 30);
  auto int1 = to_string(stageFinds[STAGE_INTEREST8]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST8]);
  auto int2 = to_string(stageFinds[STAGE_INTEREST16]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST16]);
  auto int4 = to_string(stageFinds[STAGE_INTEREST32]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST32]);
  auto knownInts = padStr(int1 + ", " + int2 + ", " + int4, 30);
  auto dict1 = to_string(stageFinds[STAGE_EXTRAS_UO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_UO]);
  auto dictionary = padStr(dict1, 30);
  auto hav1 = to_string(stageFinds[STAGE_HAVOC]) + "/" + to_string(mutation.stageCycles[STAGE_HAVOC]);
  auto havoc = padStr(hav1, 30);
  printf(cGRN Bold "%sAFL Solidity v0.0.1" cRST "\n", padStr("", 20).c_str());
  printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV5 bV bTR "\n");
  printf(bH "      run time : %s " bH "\n", formatDuration(duration).data());
  printf(bH " last new path : %s " bH "\n",formatDuration(fromLastNewPath).data());
  printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bTTR bV cGRN " overall results " cRST bV2 bV10 bV bRTR "\n");
  printf(bH "  now trying : %s" bH "    cycles done : %s" bH "\n", nowTrying.c_str(), cycleDone.c_str());
  printf(bH " stage execs : %s" bH " total branches : %s" bH "\n", stageExec.c_str(), coveredBranchesStr.c_str());
  printf(bH " total execs : %s" bH "    map density : %s" bH "\n", allExecs.c_str(), mapDensitive.c_str());
  printf(bH "  exec speed : %s" bH " count coverage : %s" bH "\n", execSpeed.c_str(), countCoverage.c_str());
  printf(bH "  cycle prog : %s" bH "                  %s" bH "\n", cycleProgress.c_str(), padStr("", 11).c_str());
  printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bBTR bV10 bV5 bTTR bV cGRN " path geometry " cRST bRTR "\n");
  printf(bH "   bit flips : %s" bH "                " bH "\n", bitflip.c_str());
  printf(bH "  byte flips : %s" bH "                " bH "\n", byteflip.c_str());
  printf(bH " arithmetics : %s" bH "                " bH "\n", arithmetic.c_str());
  printf(bH "  known ints : %s" bH "                " bH "\n", knownInts.c_str());
  printf(bH "  dictionary : %s" bH "                " bH "\n", dictionary.c_str());
  printf(bH "       havoc : %s" bH "                " bH "\n", havoc.c_str());
  printf(bBL bV50 bV5 bV bBTR bV20 bBR "\n");
}

/* Save data if interest */
FuzzItem Fuzzer::saveIfInterest(bytes data) {
  FuzzItem item(data);
  item.res = container.exec(data);
  item.wasFuzzed = false;
  totalExecs ++;
  if (hasNewBits(item.res.tracebits)) {
    queues.push_back(item);
    lastNewPath = timer.elapsed();
  }
  return item;
}

/* Start fuzzing */
void Fuzzer::start() {
  Dictionary dict(code);
  /* First test case */
  timer.restart();
  saveIfInterest(ca.randomTestcase());
  int origHitCount = queues.size();
  while (true) {
    FuzzItem curItem = queues[idx];
    Mutation mutation(curItem, dict);
    auto save = [&](bytes data) {
      auto item = saveIfInterest(data);
      showStats(mutation, item);
      return item;
    };
    if (!curItem.wasFuzzed) {
      mutation.singleWalkingBit(save);
      stageFinds[STAGE_FLIP1] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.twoWalkingBit(save);
      stageFinds[STAGE_FLIP2] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.fourWalkingBit(save);
      stageFinds[STAGE_FLIP4] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.singleWalkingByte(save);
      stageFinds[STAGE_FLIP8] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.twoWalkingByte(save);
      stageFinds[STAGE_FLIP16] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.fourWalkingByte(save);
      stageFinds[STAGE_FLIP32] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.singleArith(save);
      stageFinds[STAGE_ARITH8] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.twoArith(save);
      stageFinds[STAGE_ARITH16] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.fourArith(save);
      stageFinds[STAGE_ARITH32] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.singleInterest(save);
      stageFinds[STAGE_INTEREST8] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.twoInterest(save);
      stageFinds[STAGE_INTEREST16] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.fourInterest(save);
      stageFinds[STAGE_INTEREST32] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.overwriteWithDictionary(save);
      stageFinds[STAGE_EXTRAS_UO] += queues.size() - origHitCount;
      origHitCount = queues.size();
      mutation.havoc(virginbits, save);
      stageFinds[STAGE_HAVOC] += queues.size() - origHitCount;
      origHitCount = queues.size();
      queues[idx].wasFuzzed = true;
    } else {
      mutation.havoc(virginbits, save);
      stageFinds[STAGE_HAVOC] += queues.size() - origHitCount;
      origHitCount = queues.size();
    }
    idx = (idx + 1) % queues.size();
    if (idx == 0) queueCycle ++;
  }
}
