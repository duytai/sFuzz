#include <thread>
#include <unistd.h>
#include "Fuzzer.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "AutoDictionary.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(bytes code, ContractABI ca): ca(ca), code(code), virginbits(bytes(MAP_SIZE, 255)), container(code, ca) {
  idx = 0;
  clearScreen = false;
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

void Fuzzer::showStats(Mutation mutation, Timer timer) {
  int numLines = 16, i = 0;
  if (!clearScreen) {
    for (i = 0; i < numLines; i++) cout << endl;
    printf(CURSOR_HIDE);
    clearScreen = true;
  }
  for (i = 0; i < numLines; i++) cout << "\x1b[A";
  auto nowTrying = padStr(mutation.stageName, 17);
  auto stageExecProgress = to_string(mutation.stageCur + 1) + "/" + to_string(mutation.stageMax);
  auto stageExecPercentage = to_string((int)((float) (mutation.stageCur + 1) / mutation.stageMax * 100));
  auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", 17);
  auto totalExecs = padStr("", 17);
  auto execSpeed = padStr("", 17);
  auto cycleDone = padStr("", 11);
  auto totalBranches = padStr("", 11);
  auto mapDensitive = padStr("", 11);
  auto countCoverage = padStr("", 11);
  auto bitflip = padStr("", 30);
  auto byteflip = padStr("", 30);
  auto arith = padStr("", 30);
  auto knownInts = padStr("", 30);
  auto havoc = padStr("", 30);
  
  printf(cGRN Bold "%sAFL Solidity v0.0.1" cRST "\n", padStr("", 20).c_str());
  printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV5 bV bTR "\n");
  printf(bH "      run time : %s " bH "\n", formatDuration(timer.elapsed()).data());
  printf(bH " last new path : %s " bH "\n",formatDuration(timer.elapsed()).data());
  printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bTTR bV cGRN " overall results " cRST bV2 bV10 bV bRTR "\n");
  printf(bH "  now trying : %s" bH "     cycle done : %s" bH "\n", nowTrying.c_str(), cycleDone.c_str());
  printf(bH " stage execs : %s" bH " total branches : %s" bH "\n", stageExec.c_str(), totalBranches.c_str());
  printf(bH " total execs : %s" bH "    map density : %s" bH "\n", totalExecs.c_str(), mapDensitive.c_str());
  printf(bH "  exec speed : %s" bH " count coverage : %s" bH "\n", execSpeed.c_str(), countCoverage.c_str());
  printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bBTR bV10 bV5 bTTR bV cGRN " path geometry " cRST bRTR "\n");
  printf(bH "   bit flips : %s" bH "                " bH "\n", bitflip.c_str());
  printf(bH "  byte flips : %s" bH "                " bH "\n", byteflip.c_str());
  printf(bH " arithmetics : %s" bH "                " bH "\n", arith.c_str());
  printf(bH "  known ints : %s" bH "                " bH "\n", knownInts.c_str());
  printf(bH "       havoc : %s" bH "                " bH "\n", havoc.c_str());
  printf(bBL bV50 bV5 bV bBTR bV20 bBR "\n");
}

/* Save data if interest */
FuzzItem Fuzzer::saveIfInterest(bytes data) {
  FuzzItem item(data);
  item.res = container.exec(data);
  item.wasFuzzed = false;
  if (hasNewBits(item.res.tracebits)) {
    queues.push_back(item);
  }
  return item;
}

/* Start fuzzing */
void Fuzzer::start() {
  Timer timer;
  Dictionary dict(code);
  AutoDictionary autoDict;
  /* First test case */
  saveIfInterest(ca.randomTestcase());
  while (true) {
    FuzzItem & curItem = queues[idx];
    Mutation mutation(curItem, dict, autoDict);
    auto save = [&](bytes data) {
      FuzzItem item = saveIfInterest(data);
      showStats(mutation, timer);
      return item;
    };
    if (!curItem.wasFuzzed) {
      mutation.singleWalkingBit(save);
//      mutation.twoWalkingBit(save);
//      mutation.fourWalkingBit(save);
//      mutation.singleWalkingByte(save);
//      mutation.twoWalkingByte(save);
//      mutation.fourWalkingByte(save);
//      mutation.singleArith(save);
//      mutation.twoArith(save);
//      mutation.fourArith(save);
//      mutation.singleInterest(save);
//      mutation.twoInterest(save);
//      mutation.fourInterest(save);
//      if (dict.extras.size()) {
//        mutation.overwriteWithDictionary(save);
//        mutation.insertWithDictionary(save);
//      }
//      if (autoDict.extras.size()) {
//        mutation.overwriteWithAutoDictionary(save);
//      }
      curItem.wasFuzzed = true;
    }
//    mutation.havoc(save);
//    if (mutation.splice(save, queues)) {
//      mutation.havoc(save);
//    };
    //idx = (idx + 1) % queues.size();
    break;
  }
}
