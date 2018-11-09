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
Fuzzer::Fuzzer(bytes code, ContractABI ca): ca(ca), code(code), virginbits(bytes(MAP_SIZE, 255)){}

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

/* Start fuzzing */
void Fuzzer::start() {
  /* Statistic information */
  TargetContainer container(code, ca);
  Dictionary dict(code);
  AutoDictionary autoDict;
  vector<FuzzItem> queues;
  /* Handle new created testcase */
  auto commomFuzzStuff = [&](bytes data) {
    FuzzItem item(data);
    item.res = container.exec(data);
    item.wasFuzzed = false;
    if (hasNewBits(item.res.tracebits)) {
      queues.push_back(item);
    }
    return item;
  };
  /* Exec the sample testcase first */
  commomFuzzStuff(ca.randomTestcase());
  /* Jump to fuzz round */
  int idx = 0;
  while (true) {
    FuzzItem & curItem = queues[idx];
    Mutation mutation(curItem, dict, autoDict);
    if (!curItem.wasFuzzed) {
      mutation.singleWalkingBit(commomFuzzStuff);
      mutation.twoWalkingBit(commomFuzzStuff);
      mutation.fourWalkingBit(commomFuzzStuff);
      mutation.singleWalkingByte(commomFuzzStuff);
      mutation.twoWalkingByte(commomFuzzStuff);
      mutation.fourWalkingByte(commomFuzzStuff);
      mutation.singleArith(commomFuzzStuff);
      mutation.twoArith(commomFuzzStuff);
      mutation.fourArith(commomFuzzStuff);
      mutation.singleInterest(commomFuzzStuff);
      mutation.twoInterest(commomFuzzStuff);
      mutation.fourInterest(commomFuzzStuff);
      if (dict.extras.size()) {
        mutation.overwriteWithDictionary(commomFuzzStuff);
        mutation.insertWithDictionary(commomFuzzStuff);
      }
      if (autoDict.extras.size()) {
        mutation.overwriteWithAutoDictionary(commomFuzzStuff);
      }
      curItem.wasFuzzed = true;
    }
    mutation.havoc(commomFuzzStuff);
    if (mutation.splice(commomFuzzStuff, queues)) {
      mutation.havoc(commomFuzzStuff);
    };
    idx = (idx + 1) % queues.size();
  }
}
