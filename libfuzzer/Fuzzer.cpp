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

void Fuzzer::showStats(Mutation, Timer timer) {
  int numLines = 16, i = 0;
  if (!clearScreen) {
    for (i = 0; i < numLines; i++) cout << endl;
    printf(CURSOR_HIDE);
    clearScreen = true;
  }
  for (i = 0; i < numLines; i++) cout << "\x1b[A";
  printf(cGRN Bold "                    AFL Solidity v0.0.1                    " cRST "\n");
  printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV bTR "\n");
  printf(bH "      run time : %s " bH "\n", formatDuration(timer.elapsed()).data());
  printf(bH " last new path : %s " bH "\n",formatDuration(timer.elapsed()).data());
  printf(bLTR bV5 cGRN " stage progress " cRST bV10 bTTR bV cGRN " overall results " cRST bV2 bV10 bV bRTR "\n");
  printf(bH "  now trying :              " bH "     cycle done :            " bH "\n");
  printf(bH " stage execs :              " bH " total branches :            " bH "\n");
  printf(bH " total execs :              " bH "    map density :            " bH "\n");
  printf(bH "  exec speed :              " bH " count coverage :            " bH "\n");
  printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bBTR bV10 bV5 bTTR bV cGRN " path geometry " cRST bRTR "\n");
  printf(bH "   bit flips :                           " bH "                " bH "\n");
  printf(bH "  byte flips :                           " bH "                " bH "\n");
  printf(bH " arithmetics :                           " bH "                " bH "\n");
  printf(bH "  known ints :                           " bH "                " bH "\n");
  printf(bH "       havoc :                           " bH "                " bH "\n");
  printf(bBL bV50 bV bBTR bV20 bBR "\n");
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
      mutation.twoWalkingBit(save);
      mutation.fourWalkingBit(save);
      mutation.singleWalkingByte(save);
      mutation.twoWalkingByte(save);
      mutation.fourWalkingByte(save);
      mutation.singleArith(save);
      mutation.twoArith(save);
      mutation.fourArith(save);
      mutation.singleInterest(save);
      mutation.twoInterest(save);
      mutation.fourInterest(save);
      if (dict.extras.size()) {
        mutation.overwriteWithDictionary(save);
        mutation.insertWithDictionary(save);
      }
      if (autoDict.extras.size()) {
        mutation.overwriteWithAutoDictionary(save);
      }
      curItem.wasFuzzed = true;
    }
    mutation.havoc(save);
    if (mutation.splice(save, queues)) {
      mutation.havoc(save);
    };
    idx = (idx + 1) % queues.size();
  }
}
