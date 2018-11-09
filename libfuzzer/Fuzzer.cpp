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
  Dictionary dict(code);
  AutoDictionary autoDict;
  /* First test case */
  saveIfInterest(ca.randomTestcase());
  while (true) {
    FuzzItem & curItem = queues[idx];
    Mutation mutation(curItem, dict, autoDict);
    auto save = [&](bytes data){ return saveIfInterest(data);};
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
