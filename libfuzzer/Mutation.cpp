#include "Mutation.h"
#include "Util.h"

using namespace std;
using namespace fuzzer;

Mutation::Mutation(FuzzItem item): curFuzzItem(item), dataSize(item.data.size()) {
  effCount = 0;
  eff = bytes(effALen(dataSize), 0);
  eff[0] = 1;
  if (effAPos(dataSize - 1) != 0) {
    eff[effAPos(dataSize - 1)] = 1;
    effCount ++;
  }
}

void Mutation::flipbit(int pos) {
  curFuzzItem.data[pos >> 3] ^= (128 >> (pos & 7));
}

void Mutation::singleWalkingBit(OnMutateFunc cb) {
  int maxStage = dataSize << 3;
  for (int i = 0; i < maxStage ; i += 1) {
    flipbit(i);
    cb(curFuzzItem.data);
    flipbit(i);
  }
}

void Mutation::twoWalkingBit(OnMutateFunc cb) {
  int maxStage = (dataSize << 3) - 1;
  for (int i = 0; i < maxStage; i += 1) {
    flipbit(i);
    flipbit(i + 1);
    cb(curFuzzItem.data);
    flipbit(i);
    flipbit(i + 1);
  }
}

void Mutation::fourWalkingBit(OnMutateFunc cb) {
  int maxStage = (dataSize << 3) - 3;
  for (int i = 0; i < maxStage; i += 1) {
    flipbit(i);
    flipbit(i + 1);
    flipbit(i + 2);
    flipbit(i + 3);
    cb(curFuzzItem.data);
    flipbit(i);
    flipbit(i + 1);
    flipbit(i + 2);
    flipbit(i + 3);
  }
}

void Mutation::singleWalkingByte(OnMutateFunc cb) {
  for (int i = 0; i < dataSize; i += 1) {
    curFuzzItem.data[i] ^= 0xFF;
    FuzzItem item = cb(curFuzzItem.data);
    /* We also use this stage to pull off a simple trick: we identify
     bytes that seem to have no effect on the current execution path
     even when fully flipped - and we skip them during more expensive
     deterministic stages, such as arithmetics or known ints. */
    if (!eff[effAPos(i)]) {
      if (item.res.cksum != curFuzzItem.res.cksum) {
        eff[effAPos(i)] = 1;
        effCount += 1;
      }
    }
    curFuzzItem.data[i] ^= 0xFF;
  }
  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
   whole thing as worth fuzzing, since we wouldn't be saving much time
   anyway. */
  if (effCount != effALen(dataSize) && effCount * 100 / effALen(dataSize) > EFF_MAX_PERC) {
    eff = bytes(effALen(dataSize), 1);
  }
}

void Mutation::twoWalkingByte(OnMutateFunc cb) {
  int maxStage = dataSize - 1;
  uint8_t *buf = &curFuzzItem.data[0];
  for (int i = 0; i < maxStage; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)]) {
      continue;
    }
    *(uint16_t*)(buf + i) ^= 0xFFFF;
    cb(curFuzzItem.data);
    *(uint16_t*)(buf + i) ^= 0xFFFF;
  }
}

void Mutation::fourWalkingByte(OnMutateFunc cb) {
  int maxStage = dataSize - 3;
  uint8_t *buf = &curFuzzItem.data[0];
  for (int i = 0; i < maxStage; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)] &&
        !eff[effAPos(i + 2)] && !eff[effAPos(i + 3)]) {
      continue;
    }
    *(uint32_t*)(buf + i) ^= 0xFFFFFFFF;
    cb(curFuzzItem.data);
    *(uint32_t*)(buf + i) ^= 0xFFFFFFFF;
  }
}

void Mutation::singleArith(OnMutateFunc cb) {
  for (int i = 0; i < dataSize; i += 1) {
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)]) {
      continue;
    }
    byte orig = curFuzzItem.data[i];
    for (int j = 1; j <= ARITH_MAX; j += 1) {
      byte r = orig ^ (orig + j);
      if (!couldBeBitflip(r)) {
        curFuzzItem.data[i] = orig + j;
        cb(curFuzzItem.data);
      }
      r = orig ^ (orig - j);
      if (!couldBeBitflip(r)) {
        curFuzzItem.data[i] = orig - j;
        cb(curFuzzItem.data);
      }
      curFuzzItem.data[i] = orig;
    }
  }
}

void Mutation::twoArith(OnMutateFunc cb) {
  byte *buf = &curFuzzItem.data[0];
  for (int i = 0; i < dataSize - 1; i += 1) {
    uint16_t orig = *(uint16_t*)(buf + i);
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)]) {
      continue;
    }
    for (int j = 0; j < ARITH_MAX; j += 1) {
      uint16_t r1 = orig ^ (orig + j);
      uint16_t r2 = orig ^ (orig - j);
      uint16_t r3 = orig ^ swap16(swap16(orig) + j);
      uint16_t r4 = orig ^ swap16(swap16(orig) - j);
      if ((orig & 0xFF) + j > 0xFF && !couldBeBitflip(r1)) {
        *(uint16_t*)(buf + i) = orig + j;
        cb(curFuzzItem.data);
      }
      if ((orig & 0xFF) < j && !couldBeBitflip(r2)) {
        *(uint16_t*)(buf + i) = orig - j;
        cb(curFuzzItem.data);
      }
      if ((orig >> 8) + j > 0xFF && !couldBeBitflip(r3)) {
        *(uint16_t*)(buf + i) = swap16(swap16(orig) + j);
        cb(curFuzzItem.data);
      };
      if ((orig >> 8) < j && !couldBeBitflip(r4)) {
        *(uint16_t*)(buf + i) = swap16(swap16(orig) - j);
        cb(curFuzzItem.data);
      };
      *(uint16_t*)(buf + i) = orig;
    }
  }
}

void Mutation::fourArith(OnMutateFunc cb) {
  byte *buf = &curFuzzItem.data[0];
  for (int i = 0; i < dataSize - 3; i += 1) {
    uint32_t orig = *(uint32_t*)(buf + i);
    /* Let's consult the effector map... */
    if (!eff[effAPos(i)] && !eff[effAPos(i + 1)] && !eff[effAPos(i + 2)] && !eff[effAPos(i + 3)]) {
      continue;
    }
    for (int j = 0; j < ARITH_MAX; j += 1) {
      uint32_t r1 = orig ^ (orig + j);
      uint32_t r2 = orig ^ (orig - j);
      uint32_t r3 = orig ^ swap32(swap32(orig) + j);
      uint32_t r4 = orig ^ swap32(swap32(orig) - j);
      if ((orig & 0xFFFF) + j > 0xFFFF && !couldBeBitflip(r1)) {
        *(uint32_t*)(buf + i) = orig + j;
        cb(curFuzzItem.data);
      }
      if ((orig & 0xFFFF) < (uint32_t)j && !couldBeBitflip(r2)) {
        *(uint32_t*)(buf + i) = orig - j;
        cb(curFuzzItem.data);
      };
      if ((swap32(orig) & 0xFFFF) + j > 0xFFFF && !couldBeBitflip(r3)) {
        *(uint32_t*)(buf + i) = swap32(swap32(orig) + j);
        cb(curFuzzItem.data);
      };
      if ((swap32(orig) & 0xFFFF) < (uint32_t) j && !couldBeBitflip(r4)) {
        *(uint32_t*)(buf + i) = swap32(swap32(orig) - j);
        cb(curFuzzItem.data);
      };
      *(uint32_t*)(buf + i) = orig;
    }
  }
}
